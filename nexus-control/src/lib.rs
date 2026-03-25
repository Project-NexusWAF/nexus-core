pub mod auth;
pub mod http;
pub mod ops;
pub mod server;
pub mod stats;

pub mod proto {
  tonic::include_proto!("nexus.control");
}

use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use nexus_config::{Config, LiveConfig};
use nexus_lb::LoadBalancer;
use nexus_pipeline::Pipeline;
use nexus_store::{LogWriter, StorePool};
use parking_lot::RwLock;

use crate::stats::ConfigLogEntry;

/// State shared between gRPC and REST handlers.
/// Built by `nexus-gateway` and injected into this crate.
pub struct ControlAppState {
  pub config: Arc<Config>,
  pub live_config: LiveConfig,
  pub pipeline: RwLock<Pipeline>,
  pub load_balancer: Arc<RwLock<Arc<LoadBalancer>>>,
  pub config_version: Arc<AtomicU64>,
  pub config_log: Arc<RwLock<Vec<ConfigLogEntry>>>,
  pub requests_total: AtomicU64,
  pub blocked_total: AtomicU64,
  pub rate_limited_total: AtomicU64,
  pub store: Option<Arc<StorePool>>,
  pub log_writer: Option<Arc<LogWriter>>,
  pub admin_token: String,
}
