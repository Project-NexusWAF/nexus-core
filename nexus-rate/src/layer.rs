use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use tracing::warn;

use nexus_common::{Decision, InnerLayer, RequestContext, Result};

use crate::limiter::{RateDecision, RateLimiter};
use crate::policy::RatePolicy;

/// The rate-limiting layer — wraps `RateLimiter` behind the `Layer` trait.
///
/// Priority: 0 — runs first, before any inspection layers.
/// Reasoning: if a client is rate-limited we don't need to waste CPU on
/// regex matching or grammar parsing.
pub struct RateLayer {
  limiter: Arc<RateLimiter>,
  cleanup_interval: Duration,
  cleanup_ttl: Duration,
}

impl RateLayer {
  pub fn new(limiter: Arc<RateLimiter>, cleanup_interval: Duration, cleanup_ttl: Duration) -> Self {
    Self {
      limiter,
      cleanup_interval,
      cleanup_ttl,
    }
  }

  pub fn from_config(cfg: &nexus_config::RateConfig) -> Self {
    let policy = RatePolicy::from_config(cfg);
    let limiter = RateLimiter::new(policy);
    Self::new(
      limiter,
      Duration::from_secs(cfg.cleanup_interval_secs),
      // Buckets are evicted if idle for 5× the cleanup interval
      Duration::from_secs(cfg.cleanup_interval_secs * 5),
    )
  }

  /// Get a handle to the underlying limiter (for control-plane policy updates).
  pub fn limiter(&self) -> Arc<RateLimiter> {
    Arc::clone(&self.limiter)
  }
}

#[async_trait]
impl InnerLayer for RateLayer {
  fn name(&self) -> &'static str {
    "rate"
  }

  fn priority(&self) -> u8 {
    0 // first layer — fastest possible rejection
  }

  async fn init(&self) -> Result<()> {
    // Start the background cleanup task
    let limiter = Arc::clone(&self.limiter);
    let interval = self.cleanup_interval;
    let ttl = self.cleanup_ttl;
    tokio::spawn(async move {
      limiter.start_cleanup(interval, ttl).await;
    });
    Ok(())
  }

  async fn analyse(&self, ctx: &mut RequestContext) -> Result<Decision> {
    let decision = self.limiter.check(ctx.client_ip);

    match decision {
      RateDecision::Allowed { remaining } => {
        ctx.rate_limit_remaining = Some(remaining);
        Ok(Decision::Allow)
      }

      RateDecision::Limited { retry_after_secs } => {
        warn!(
            ip         = %ctx.client_ip,
            request_id = %ctx.id,
            retry_after = retry_after_secs,
            "Rate limit exceeded"
        );
        ctx.rate_limited = true;
        ctx
          .meta
          .insert("rate_retry_after".into(), retry_after_secs.to_string());
        Ok(Decision::RateLimit {
          retry_after_seconds: retry_after_secs.min(u32::MAX as u64) as u32,
        })
      }

      RateDecision::Blocked => {
        warn!(
            ip         = %ctx.client_ip,
            request_id = %ctx.id,
            "IP is on permanent blocklist"
        );
        ctx.tag("blocklisted", self.name());
        Ok(Decision::block(
          "IP address is permanently blocked",
          nexus_common::BlockCode::ProtocolViolation,
        ))
      }

      RateDecision::Disabled => Ok(Decision::Allow),
    }
  }
}
