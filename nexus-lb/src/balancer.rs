use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use parking_lot::RwLock;
use nexus_common::NexusError;
use nexus_common::Result;
use nexus_config::schema::{LbAlgorithm, LbConfig};
use crate::upstream::{Upstream, UpstreamStatus};

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
        let routable: Vec<&Upstream> = upstreams
            .iter()
            .filter(|u| u.is_routable())
            .collect();

        if routable.is_empty() {
            return Err(NexusError::NoHealthyUpstream);
        }

        let addr = match self.algorithm {
            LbAlgorithm::RoundRobin => {
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % routable.len();
                routable[idx].addr.clone()
            }
            LbAlgorithm::WeightedRoundRobin => {
                let pool: Vec<&str> = routable
                    .iter()
                    .flat_map(|u| std::iter::repeat_n(u.addr.as_str(), u.weight as usize))
                    .collect();
                if pool.is_empty() {
                // Fallback: all weights are zero, use plain round-robin
                    let idx = self.counter.fetch_add(1, Ordering::Relaxed) % routable.len();
                    routable[idx].addr.clone()
                } else {
                    let idx = self.counter.fetch_add(1, Ordering::Relaxed) % pool.len();
                    pool[idx].to_string()
    }
}
            LbAlgorithm::LeastConnections => {
                // TODO: track active connections
                let idx = self.counter.fetch_add(1, Ordering::Relaxed) % routable.len();
                routable[idx].addr.clone()
            }
        };

        Ok(addr)
    }

    pub fn record_success(&self, addr: &str) {
        let mut upstreams = self.upstreams.write();
        if let Some(u) = upstreams.iter_mut().find(|u| u.addr == addr) {
            u.consecutive_failures = 0;
            u.consecutive_successes += 1;
            if u.consecutive_successes >= self.healthy_threshold
            && u.status != UpstreamStatus::Healthy
        {
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
        self.upstreams
            .read()
            .iter()
            .map(|u| (u.addr.clone(), u.status.clone()))
            .collect()
    }
}