use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use dashmap::DashMap;
use parking_lot::RwLock;
use tracing::{debug, info, warn};

use crate::bucket::TokenBucket;
use crate::policy::{PreCheckResult, RatePolicy};

/// The core rate limiter.
///
/// Holds:
///   - `DashMap<IpAddr, TokenBucket>` — one bucket per seen IP.
///     DashMap shards internally, so concurrent access from N Tokio tasks
///     only locks one shard (1/64 of the map) at a time.
///   - `RwLock<RatePolicy>` — the current policy, hot-swappable.
///
/// Thread-safety: `Arc<RateLimiter>` can be cloned freely across tasks.
pub struct RateLimiter {
  buckets: DashMap<IpAddr, TokenBucket>,
  policy: RwLock<RatePolicy>,
}

/// The result of a single rate-limit check.
#[derive(Debug, Clone)]
pub enum RateDecision {
  Allowed { remaining: u32 },
  Limited { retry_after_secs: u64 },
  Blocked,
  Disabled,
}

impl RateLimiter {
  pub fn new(policy: RatePolicy) -> Arc<Self> {
    Arc::new(Self {
      buckets: DashMap::with_capacity_and_hasher(1024, Default::default()),
      policy: RwLock::new(policy),
    })
  }
  pub fn check(&self, ip: IpAddr) -> RateDecision {
    let policy = self.policy.read();

    if !policy.enabled {
      return RateDecision::Disabled;
    }

    if let Some(result) = policy.pre_check(&ip) {
      return match result {
        PreCheckResult::PermanentAllow => RateDecision::Allowed {
          remaining: u32::MAX,
        },
        PreCheckResult::PermanentBlock => RateDecision::Blocked,
      };
    }

    let rps = policy.requests_per_second;
    let burst = policy.burst_capacity;

    drop(policy);
    let mut bucket = self
      .buckets
      .entry(ip)
      .or_insert_with(|| TokenBucket::new(burst, rps));

    // Ensure existing buckets immediately reflect the current policy.
    // or_insert_with only runs the closure for *new* entries, so a bucket
    // created under an old policy would otherwise keep its old capacity and
    // refill rate indefinitely. reconfigure() updates both fields in-place
    // and clamps the current token count to the new capacity if it shrank.
    bucket.reconfigure(burst, rps);

    match bucket.try_consume() {
      Ok(remaining) => {
        debug!(ip = %ip, remaining, "Rate check: allowed");
        RateDecision::Allowed { remaining }
      }
      Err(retry_after_secs) => {
        debug!(ip = %ip, retry_after_secs, "Rate check: limited");
        RateDecision::Limited { retry_after_secs }
      }
    }
  }

  pub fn update_policy(&self, new_policy: RatePolicy) {
    let mut policy = self.policy.write();
    *policy = new_policy;
    info!("Rate policy updated");
  }

  pub fn policy_snapshot(&self) -> RatePolicy {
    self.policy.read().clone()
  }

  pub fn bucket_count(&self) -> usize {
    self.buckets.len()
  }

  pub fn cleanup(&self, ttl: Duration) -> usize {
    let before = self.buckets.len();
    self.buckets.retain(|_ip, bucket| !bucket.is_idle(ttl));
    let evicted = before - self.buckets.len();
    if evicted > 0 {
      info!(
        evicted,
        remaining = self.buckets.len(),
        "Rate limiter cleanup"
      );
    }
    evicted
  }

  pub async fn start_cleanup(self: Arc<Self>, interval: Duration, ttl: Duration) {
    let interval = if interval.is_zero() {
      let safe = Duration::from_secs(1);
      warn!(
        "start_cleanup called with a zero interval, which would panic in \
         tokio::time::interval; clamping to {:?}",
        safe
      );
      safe
    } else {
      interval
    };
    let mut ticker = tokio::time::interval(interval);
    loop {
      ticker.tick().await;
      self.cleanup(ttl);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::Ipv4Addr;

  fn ip(last: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(10, 0, 0, last))
  }

  fn make_limiter(rps: u32, burst: u32) -> Arc<RateLimiter> {
    let policy = RatePolicy {
      enabled: true,
      requests_per_second: rps,
      burst_capacity: burst,
      ..Default::default()
    };
    RateLimiter::new(policy)
  }

  #[test]
  fn allows_up_to_burst() {
    let rl = make_limiter(10, 5);
    for i in 0..5 {
      assert!(
        matches!(rl.check(ip(1)), RateDecision::Allowed { .. }),
        "request {} should be allowed",
        i
      );
    }
    // 6th request exceeds burst
    assert!(matches!(rl.check(ip(1)), RateDecision::Limited { .. }));
  }

  #[test]
  fn different_ips_have_independent_buckets() {
    let rl = make_limiter(10, 1);
    // Drain IP 1
    let _ = rl.check(ip(1));
    assert!(matches!(rl.check(ip(1)), RateDecision::Limited { .. }));
    // IP 2 is unaffected
    assert!(matches!(rl.check(ip(2)), RateDecision::Allowed { .. }));
  }

  #[test]
  fn disabled_policy_always_allows() {
    let policy = RatePolicy {
      enabled: false,
      ..Default::default()
    };
    let rl = RateLimiter::new(policy);
    for _ in 0..1000 {
      assert!(matches!(rl.check(ip(1)), RateDecision::Disabled));
    }
  }

  #[test]
  fn blocklist_denies_without_bucket() {
    let mut policy = RatePolicy::default();
    policy.blocklist.insert(ip(99));
    let rl = RateLimiter::new(policy);
    assert!(matches!(rl.check(ip(99)), RateDecision::Blocked));
    // Blocked IP never gets a bucket
    assert_eq!(rl.bucket_count(), 0);
  }

  #[test]
  fn allowlist_bypasses_limit() {
    let mut policy = RatePolicy {
      burst_capacity: 1,
      ..Default::default()
    };
    policy.allowlist.insert(ip(42));
    let rl = RateLimiter::new(policy);
    // Even after exhausting burst, allowlisted IP is always allowed
    for _ in 0..1000 {
      assert!(matches!(
        rl.check(ip(42)),
        RateDecision::Allowed {
          remaining: u32::MAX
        }
      ));
    }
  }

  #[test]
  fn cleanup_evicts_idle_buckets() {
    let rl = make_limiter(10, 10);
    let _ = rl.check(ip(5));
    assert_eq!(rl.bucket_count(), 1);
    // Evict with zero TTL — everything is "idle"
    rl.cleanup(Duration::from_secs(0));
    assert_eq!(rl.bucket_count(), 0);
  }

  #[test]
  fn policy_update_takes_effect() {
    let rl = make_limiter(1000, 1000);
    // Update to very low limit
    let new_policy = RatePolicy {
      enabled: true,
      requests_per_second: 1,
      burst_capacity: 1,
      ..Default::default()
    };
    rl.update_policy(new_policy);
    // New IPs get the new bucket params
    let _ = rl.check(ip(10)); // uses 1 token (new burst=1)
    assert!(matches!(rl.check(ip(10)), RateDecision::Limited { .. }));
  }
}
