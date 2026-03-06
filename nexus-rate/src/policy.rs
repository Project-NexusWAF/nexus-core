use std::collections::HashSet;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

/// The rate limiting policy — can be hot-updated via the control plane
/// without restarting the limiter or losing existing bucket state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RatePolicy {
  pub enabled: bool,
  pub requests_per_second: u32,
  pub burst_capacity: u32,
  pub allowlist: HashSet<IpAddr>,
  pub blocklist: HashSet<IpAddr>,
}

impl RatePolicy {
  pub fn from_config(cfg: &nexus_config::RateConfig) -> Self {
    Self {
      enabled: cfg.enabled,
      requests_per_second: cfg.requests_per_second,
      burst_capacity: cfg.burst_capacity,
      allowlist: HashSet::new(),
      blocklist: HashSet::new(),
    }
  }

  pub fn pre_check(&self, ip: &IpAddr) -> Option<PreCheckResult> {
    if self.blocklist.contains(ip) {
      return Some(PreCheckResult::PermanentBlock);
    }
    if self.allowlist.contains(ip) {
      return Some(PreCheckResult::PermanentAllow);
    }
    None
  }
}

#[derive(Debug, Clone, PartialEq)]
pub enum PreCheckResult {
  PermanentAllow,
  PermanentBlock,
}

impl Default for RatePolicy {
  fn default() -> Self {
    Self {
      enabled: true,
      requests_per_second: 1000,
      burst_capacity: 200,
      allowlist: HashSet::new(),
      blocklist: HashSet::new(),
    }
  }
}
