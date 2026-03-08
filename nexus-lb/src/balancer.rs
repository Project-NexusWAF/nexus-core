use std::sync::{
  atomic::{AtomicUsize, Ordering},
  Arc,
};

use parking_lot::RwLock;

use crate::upstream::{Upstream, UpstreamStatus};
use nexus_common::NexusError;
use nexus_common::Result;
use nexus_config::schema::{LbAlgorithm, LbConfig};

pub struct LoadBalancer {
  pub(crate) upstreams: RwLock<Vec<Upstream>>,
  pub(crate) counter: AtomicUsize,
  pub(crate) algorithm: LbAlgorithm,
  pub(crate) unhealthy_threshold: u32,
  pub(crate) healthy_threshold: u32,
}

impl LoadBalancer {
  pub fn from_config(cfg: &LbConfig) -> Arc<Self> {
    let upstreams = cfg
      .upstreams
      .iter()
      .filter(|u| u.enabled)
      .map(Upstream::from_config)
      .collect();

    Arc::new(Self {
      upstreams: RwLock::new(upstreams),
      counter: AtomicUsize::new(0),
      algorithm: cfg.algorithm.clone(),
      unhealthy_threshold: cfg.unhealthy_threshold,
      healthy_threshold: cfg.healthy_threshold,
    })
  }

  pub fn select(&self) -> Result<String> {
    let upstreams = self.upstreams.read();

    let chosen_addr = match self.algorithm {
      LbAlgorithm::RoundRobin => {
        let routable: Vec<&Upstream> = upstreams.iter().filter(|u| u.is_routable()).collect();

        if routable.is_empty() {
          return Err(NexusError::NoHealthyUpstream);
        }

        let idx = self.counter.fetch_add(1, Ordering::Relaxed) % routable.len();
        routable[idx].addr.clone()
      }

      LbAlgorithm::WeightedRoundRobin => {
        let routable: Vec<&Upstream> = upstreams.iter().filter(|u| u.is_routable()).collect();

        if routable.is_empty() {
          return Err(NexusError::NoHealthyUpstream);
        }

        let total_weight: u64 = routable.iter().map(|u| u.weight as u64).sum();

        if total_weight == 0 {
          // Fallback: all weights are zero, use plain round-robin
          let idx = self.counter.fetch_add(1, Ordering::Relaxed) % routable.len();
          routable[idx].addr.clone()
        } else {
          let offset = (self.counter.fetch_add(1, Ordering::Relaxed) as u64) % total_weight;
          let mut cumulative = 0u64;

          let chosen = routable
            .iter()
            .find(|u| {
              cumulative += u.weight as u64;
              offset < cumulative
            })
            .copied()
            .unwrap_or_else(|| routable[routable.len() - 1]);

          chosen.addr.clone()
        }
      }

      LbAlgorithm::LeastConnections => {
        let chosen = upstreams
          .iter()
          .filter(|u| u.is_routable())
          .min_by_key(|u| u.active_connections.load(Ordering::Relaxed))
          .ok_or(NexusError::NoHealthyUpstream)?;

        chosen.active_connections.fetch_add(1, Ordering::Relaxed);
        chosen.addr.clone()
      }
    };

    Ok(chosen_addr)
  }

  /// Release a connection previously acquired via `select()` in
  /// `LbAlgorithm::LeastConnections` mode.
  ///
  /// Safe to call even if the upstream has no active connections (will not underflow).
  pub fn release_connection(&self, upstream_addr: &str) {
    let upstreams = self.upstreams.read();
    if let Some(u) = upstreams.iter().find(|u| u.addr == upstream_addr) {
      let _ = u
        .active_connections
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
          current.checked_sub(1)
        });
    }
  }

  pub fn record_success(&self, addr: &str) {
    let mut upstreams = self.upstreams.write();
    if let Some(u) = upstreams.iter_mut().find(|u| u.addr == addr) {
      u.consecutive_failures = 0;
      u.consecutive_successes += 1;
      if u.consecutive_successes >= self.healthy_threshold && u.status != UpstreamStatus::Healthy {
        u.status = UpstreamStatus::Healthy;
        tracing::info!(addr = addr, "Upstream marked Healthy");
      }
    }
  }

  pub fn record_failure(&self, addr: &str) {
    let mut upstreams = self.upstreams.write();
    if let Some(u) = upstreams.iter_mut().find(|u| u.addr == addr) {
      u.consecutive_successes = 0;
      u.consecutive_failures += 1;
      if u.consecutive_failures >= self.unhealthy_threshold {
        u.status = UpstreamStatus::Unhealthy;
        tracing::warn!(
          addr = addr,
          failures = u.consecutive_failures,
          "Upstream marked Unhealthy"
        );
      }
    }
  }

  pub fn statuses(&self) -> Vec<(String, UpstreamStatus)> {
    self
      .upstreams
      .read()
      .iter()
      .map(|u| (u.addr.clone(), u.status.clone()))
      .collect()
  }
}
