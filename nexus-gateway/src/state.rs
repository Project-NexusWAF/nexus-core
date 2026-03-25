use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use nexus_config::{Config, LiveConfig};
use nexus_control::stats::ConfigLogEntry;
use nexus_control::ControlAppState;
use nexus_lb::LoadBalancer;
use nexus_pipeline::{Pipeline, PipelineBuilder};
use nexus_store::{LogWriter, StorePool};
use parking_lot::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tracing::{info, warn};

pub type HyperClient = Client<HttpConnector, Full<Bytes>>;

pub struct AppState {
  pub control: Arc<ControlAppState>,
  pub http_client: HyperClient,
  lb: Arc<RwLock<Arc<LoadBalancer>>>,
  lb_health: Mutex<Option<JoinHandle<()>>>,
}

pub struct UpstreamSelection {
  pub addr: String,
  lb: Arc<LoadBalancer>,
}

impl UpstreamSelection {
  pub fn record_success(&self) {
    self.lb.record_success(&self.addr);
  }

  pub fn record_failure(&self) {
    self.lb.record_failure(&self.addr);
  }
}

impl Drop for UpstreamSelection {
  fn drop(&mut self) {
    self.lb.release_connection(&self.addr);
  }
}

impl AppState {
  pub async fn new(
    config: Arc<Config>,
    live_config: LiveConfig,
    admin_token: String,
  ) -> anyhow::Result<Arc<Self>> {
    let pipeline = PipelineBuilder::from_config(&config);
    pipeline
      .init()
      .await
      .context("pipeline initialization failed")?;

    let (store, log_writer) = match StorePool::connect(&config.store).await {
      Ok(pool) => {
        let pool = Arc::new(pool);
        let writer = Arc::new(LogWriter::new(pool.pg.clone(), &config.store));
        info!("PostgreSQL connected");
        if let Err(error) = sync_rules_file_to_store(Arc::clone(&pool), Arc::clone(&config)).await {
          warn!(error = %error, "failed to sync rules file to PostgreSQL");
        }
        (Some(pool), Some(writer))
      }
      Err(error) => {
        warn!(error = %error, "DB unavailable, continuing without persistence");
        (None, None)
      }
    };

    let lb = LoadBalancer::from_config(&config.lb);
    let lb_handle = Arc::new(RwLock::new(Arc::clone(&lb)));
    let config_log = Arc::new(RwLock::new(vec![ConfigLogEntry {
      timestamp: Utc::now(),
      version: 1,
      status: "applied".to_string(),
      message: "initial config loaded".to_string(),
    }]));

    let control = Arc::new(ControlAppState {
      config: Arc::clone(&config),
      live_config,
      pipeline: RwLock::new(pipeline),
      load_balancer: Arc::clone(&lb_handle),
      config_version: Arc::new(AtomicU64::new(1)),
      config_log,
      requests_total: AtomicU64::new(0),
      blocked_total: AtomicU64::new(0),
      rate_limited_total: AtomicU64::new(0),
      store,
      log_writer,
      admin_token,
    });

    let lb_health = spawn_lb_health(Arc::clone(&lb), config.lb.health_check_interval_secs);

    Ok(Arc::new(Self {
      control,
      http_client: build_http_client(),
      lb: lb_handle,
      lb_health: Mutex::new(Some(lb_health)),
    }))
  }

  pub fn active_config(&self) -> Arc<Config> {
    self.control.live_config.borrow().clone()
  }

  pub fn select_upstream(&self) -> nexus_common::Result<UpstreamSelection> {
    let lb = self.lb.read().clone();
    let addr = lb.select()?;
    Ok(UpstreamSelection { addr, lb })
  }

  pub fn update_load_balancer(&self, cfg: &nexus_config::schema::LbConfig) {
    let lb = LoadBalancer::from_config(cfg);
    *self.lb.write() = Arc::clone(&lb);

    let mut guard = self.lb_health.lock();
    if let Some(handle) = guard.take() {
      handle.abort();
    }
    *guard = Some(spawn_lb_health(lb, cfg.health_check_interval_secs));
  }

  pub fn clone_pipeline(&self) -> Pipeline {
    self.control.pipeline.read().clone()
  }
}

fn build_http_client() -> HyperClient {
  Client::builder(TokioExecutor::new())
    .pool_idle_timeout(std::time::Duration::from_secs(90))
    .pool_max_idle_per_host(32)
    .build(HttpConnector::new())
}

fn spawn_lb_health(lb: Arc<LoadBalancer>, interval_secs: u64) -> JoinHandle<()> {
  let interval = Duration::from_secs(interval_secs.max(1));
  tokio::spawn(nexus_lb::health::run_health_checks(lb, interval))
}

async fn sync_rules_file_to_store(
  store: Arc<StorePool>,
  config: Arc<Config>,
) -> anyhow::Result<()> {
  let rules_path = std::path::PathBuf::from(&config.rules.rules_file);
  let content = tokio::fs::read_to_string(&rules_path)
    .await
    .with_context(|| format!("failed to read rules file {}", rules_path.display()))?;

  if content.trim().is_empty() {
    warn!(path = %rules_path.display(), "rules file is empty; skipping DB sync");
    return Ok(());
  }

  if let Some(active) = store.rules().load_active().await? {
    if active.trim() == content.trim() {
      info!(path = %rules_path.display(), "rules file already matches active PostgreSQL rules");
      return Ok(());
    }
  }

  let parsed: toml::Value =
    toml::from_str(&content).context("rules file is not valid TOML during startup sync")?;
  let version = parsed
    .get("version")
    .and_then(|v| v.as_str())
    .filter(|v| !v.trim().is_empty())
    .unwrap_or("startup-sync");

  store
    .rules()
    .save(version, &content)
    .await
    .context("failed to persist rules to PostgreSQL during startup sync")?;
  info!(version = %version, path = %rules_path.display(), "rules synced to PostgreSQL");
  Ok(())
}
