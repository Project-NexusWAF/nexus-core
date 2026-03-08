use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Context;
use bytes::Bytes;
use http_body_util::Full;
use hyper_util::client::legacy::connect::HttpConnector;
use hyper_util::client::legacy::Client;
use hyper_util::rt::TokioExecutor;
use nexus_config::{Config, LiveConfig};
use nexus_control::ControlAppState;
use nexus_pipeline::{Pipeline, PipelineBuilder};
use nexus_store::{LogWriter, StorePool};
use parking_lot::RwLock;
use tracing::{info, warn};

pub type HyperClient = Client<HttpConnector, Full<Bytes>>;

pub struct AppState {
  pub control: Arc<ControlAppState>,
  pub http_client: HyperClient,
  pub upstream_rr: AtomicUsize,
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

    let control = Arc::new(ControlAppState {
      config: Arc::clone(&config),
      live_config,
      pipeline: RwLock::new(pipeline),
      config_version: Arc::new(AtomicU64::new(1)),
      requests_total: AtomicU64::new(0),
      blocked_total: AtomicU64::new(0),
      rate_limited_total: AtomicU64::new(0),
      store,
      log_writer,
      admin_token,
    });

    Ok(Arc::new(Self {
      control,
      http_client: build_http_client(),
      upstream_rr: AtomicUsize::new(0),
    }))
  }

  pub fn active_config(&self) -> Arc<Config> {
    self.control.live_config.borrow().clone()
  }

  pub fn select_upstream(&self) -> Option<nexus_config::UpstreamConfig> {
    let cfg = self.active_config();
    let enabled: Vec<_> = cfg
      .lb
      .upstreams
      .iter()
      .filter(|upstream| upstream.enabled)
      .cloned()
      .collect();
    if enabled.is_empty() {
      return None;
    }

    let index = self.upstream_rr.fetch_add(1, Ordering::Relaxed) % enabled.len();
    enabled.get(index).cloned()
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
