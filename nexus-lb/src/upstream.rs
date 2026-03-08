use nexus_config::UpstreamConfig;
use serde::{Deserialize, Serialize};
use std::sync::atomic::AtomicUsize;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UpstreamStatus {
  Healthy,
  Unhealthy,
  Unknown,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Upstream {
  pub name: String,
  pub addr: String,
  pub weight: u32,
  pub status: UpstreamStatus,
  pub consecutive_failures: u32,
  pub consecutive_successes: u32,
  #[serde(skip, default = "default_active_connections")]
  pub active_connections: AtomicUsize,
}

fn default_active_connections() -> AtomicUsize {
  AtomicUsize::new(0)
}

impl Clone for Upstream {
  fn clone(&self) -> Self {
    Self {
      name: self.name.clone(),
      addr: self.addr.clone(),
      weight: self.weight,
      status: self.status.clone(),
      consecutive_failures: self.consecutive_failures,
      consecutive_successes: self.consecutive_successes,
      active_connections: AtomicUsize::new(
        self
          .active_connections
          .load(std::sync::atomic::Ordering::Relaxed),
      ),
    }
  }
}

impl Upstream {
  pub fn is_routable(&self) -> bool {
    matches!(
      self.status,
      UpstreamStatus::Healthy | UpstreamStatus::Unknown
    )
  }

  pub fn from_config(cfg: &UpstreamConfig) -> Self {
    Self {
      name: cfg.name.clone(),
      addr: cfg.addr.clone(),
      weight: cfg.weight,
      status: UpstreamStatus::Unknown,
      consecutive_failures: 0,
      consecutive_successes: 0,
      active_connections: AtomicUsize::new(0),
    }
  }
}
