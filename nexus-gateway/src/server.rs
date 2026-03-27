use std::net::SocketAddr;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::Context;
use axum::{
  routing::any,
  Router,
};
use chrono::Utc;
use nexus_config::SlackSeverity;
use nexus_control::proto::control_plane_server::ControlPlaneServer;
use nexus_control::server::ControlServer;
use nexus_control::stats::ConfigLogEntry;
use nexus_pipeline::PipelineBuilder;
use tracing_subscriber::EnvFilter;

use crate::proxy;
use crate::state::AppState;

pub fn init_tracing() {
  let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
    EnvFilter::new("info,tower_http=info,nexus_gateway=debug,nexus_control=debug")
  });
  let _ = tracing_subscriber::fmt().with_env_filter(filter).try_init();
}

pub fn spawn_config_reload_task(state: Arc<AppState>) {
  tokio::spawn(async move {
    let mut rx = state.control.live_config.clone();
    loop {
      if rx.changed().await.is_err() {
        tracing::warn!("config watcher channel closed; stopping reload task");
        return;
      }

      let cfg = rx.borrow().clone();
      state.update_load_balancer(&cfg.lb);
      let (telemetry, anomaly_state) = {
        let current = state.control.pipeline.read();
        (current.telemetry(), current.anomaly_state())
      };
      let pipeline = PipelineBuilder::from_config_with_state(
        &cfg,
        telemetry,
        anomaly_state,
      );
      match pipeline.init().await {
        Ok(()) => {
          *state.control.pipeline.write() = pipeline;
          let version = state.control.config_version.fetch_add(1, Ordering::SeqCst) + 1;
          tracing::info!(config_version = version, "live config applied to pipeline");
          state.slack_alerts.notify_system(
            "Config Reload Applied",
            format!("Live configuration reloaded successfully. Version {version}."),
            SlackSeverity::Low,
          );
          push_config_log(
            &state,
            ConfigLogEntry {
              timestamp: Utc::now(),
              version,
              status: "applied".to_string(),
              message: "config reloaded from watcher".to_string(),
            },
          );
        }
        Err(error) => {
          tracing::error!(error = %error, "failed to apply live config update; keeping current pipeline");
          let version = state.control.config_version.load(Ordering::Relaxed);
          state.slack_alerts.notify_system(
            "Config Reload Failed",
            format!("Live configuration reload failed: {error}"),
            SlackSeverity::High,
          );
          push_config_log(
            &state,
            ConfigLogEntry {
              timestamp: Utc::now(),
              version,
              status: "error".to_string(),
              message: format!("config reload failed: {error}"),
            },
          );
        }
      }
    }
  });
}

fn push_config_log(state: &Arc<AppState>, entry: ConfigLogEntry) {
  let mut log = state.control.config_log.write();
  log.push(entry);
  const MAX_ENTRIES: usize = 200;
  if log.len() > MAX_ENTRIES {
    let excess = log.len() - MAX_ENTRIES;
    log.drain(0..excess);
  }
}

pub async fn run_gateway(
  addr: String,
  state: Arc<AppState>,
  tls: Option<axum_server::tls_rustls::RustlsConfig>,
) -> anyhow::Result<()> {
  let router = Router::new()
    .fallback(any(proxy::proxy_handler))
    .with_state(state);
  let service = router.into_make_service_with_connect_info::<SocketAddr>();

  if let Some(tls) = tls {
    tracing::info!(addr = %addr, "HTTPS proxy listening with TLS termination");
    axum_server::bind_rustls(
      addr.parse()
        .with_context(|| format!("invalid gateway listen addr: {addr}"))?,
      tls,
    )
    .serve(service)
    .await
    .context("gateway TLS server failed")
  } else {
    let listener = tokio::net::TcpListener::bind(&addr)
      .await
      .with_context(|| format!("failed to bind gateway listener on {addr}"))?;
    tracing::info!(addr = %addr, "HTTP proxy listening");
    axum::serve(listener, service)
      .await
      .context("gateway server failed")
  }
}

pub async fn run_grpc(addr: String, state: Arc<AppState>) -> anyhow::Result<()> {
  let socket_addr: SocketAddr = addr
    .parse()
    .with_context(|| format!("invalid gRPC addr: {addr}"))?;
  tracing::info!(addr = %addr, "gRPC control plane listening");

  tonic::transport::Server::builder()
    .add_service(ControlPlaneServer::new(ControlServer::new(Arc::clone(
      &state.control,
    ))))
    .serve(socket_addr)
    .await
    .context("gRPC control plane failed")
}

pub async fn run_rest(addr: String, state: Arc<AppState>) -> anyhow::Result<()> {
  let listener = tokio::net::TcpListener::bind(&addr)
    .await
    .with_context(|| format!("failed to bind REST listener on {addr}"))?;
  tracing::info!(addr = %addr, "REST API and dashboard listening");
  let router = nexus_control::http::rest_router(Arc::clone(&state.control));
  axum::serve(listener, router)
    .await
    .context("REST server failed")
}
