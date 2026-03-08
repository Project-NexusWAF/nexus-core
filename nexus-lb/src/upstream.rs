use serde::{Deserialize, Serialize};
use nexus_config::UpstreamConfig;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UpstreamStatus {
    Healthy,
    Unhealthy,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    pub name: String,
    pub addr: String,
    pub weight: u32,
    pub status: UpstreamStatus,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
}

impl Upstream {
    pub fn is_routable(&self) -> bool {
        matches!(self.status, UpstreamStatus::Healthy | UpstreamStatus::Unknown)
    }

    pub fn from_config(cfg: &UpstreamConfig) -> Self {
        Self {
            name: cfg.name.clone(),
            addr: cfg.addr.clone(),
            weight: cfg.weight,
            status: UpstreamStatus::Unknown,
            consecutive_failures: 0,
            consecutive_successes: 0,
        }
    }
}