/// A single token bucket for one IP address.
///
/// Stored inside a `DashMap` value, protected by the map's shard lock.
/// The struct is intentionally small (3 fields, 24 bytes) so that
/// cache lines holding many buckets are not evicted.
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct TokenBucket {
  tokens: f64,
  capacity: f64,
  refill_rate_per_ns: f64,
  last_refill: Instant,
}

impl TokenBucket {
  pub fn new(capacity: u32, requests_per_second: u32) -> Self {
    assert!(
      capacity > 0,
      "TokenBucket::new: capacity must be > 0, got 0"
    );
    assert!(
      requests_per_second > 0,
      "TokenBucket::new: requests_per_second must be > 0, got 0 (would make refill_rate_per_ns zero, causing division by zero in try_consume)"
    );
    Self {
      tokens: capacity as f64,
      capacity: capacity as f64,
      refill_rate_per_ns: requests_per_second as f64 / 1_000_000_000.0,
      last_refill: Instant::now(),
    }
  }
  pub fn try_consume(&mut self) -> Result<u32, u64> {
    self.refill();
    if self.tokens >= 1.0 {
      self.tokens -= 1.0;
      Ok(self.tokens as u32)
    } else {
      let deficit = 1.0 - self.tokens;
      let wait_ns = deficit / self.refill_rate_per_ns;
      let retry_after_secs = (wait_ns / 1_000_000_000.0).ceil() as u64;
      Err(retry_after_secs.max(1))
    }
  }

  fn refill(&mut self) {
    let now = Instant::now();
    let elapsed_ns = now.duration_since(self.last_refill).as_nanos() as f64;
    let new_tokens = elapsed_ns * self.refill_rate_per_ns;

    if new_tokens > 0.0 {
      self.tokens = (self.tokens + new_tokens).min(self.capacity);
      self.last_refill = now;
    }
  }
  /// Update the bucket's capacity and refill rate in-place, preserving
  /// accumulated tokens where possible.
  ///
  /// Called after a policy hot-update so that existing buckets immediately
  /// adopt the new limits rather than keeping their old parameters until
  /// they are evicted and recreated.
  ///
  /// Token preservation rules:
  /// - If the new capacity is larger, the current token count is kept as-is
  ///   (the client keeps what they earned, and the ceiling rises).
  /// - If the new capacity is smaller, the current token count is clamped
  ///   down to the new capacity (we cannot hold more than the new ceiling).
  pub fn reconfigure(&mut self, capacity: u32, requests_per_second: u32) {
    assert!(
      capacity > 0,
      "TokenBucket::reconfigure: capacity must be > 0, got 0"
    );
    assert!(
      requests_per_second > 0,
      "TokenBucket::reconfigure: requests_per_second must be > 0, got 0 (would make refill_rate_per_ns zero, causing division by zero in try_consume)"
    );
    let new_capacity = capacity as f64;
    self.capacity = new_capacity;
    self.refill_rate_per_ns = requests_per_second as f64 / 1_000_000_000.0;
    // Clamp existing tokens down to the new ceiling; never inflate them
    // upward (that would grant tokens the client hasn't earned).
    if self.tokens > new_capacity {
      self.tokens = new_capacity;
    }
  }

  pub fn is_idle(&self, ttl: Duration) -> bool {
    self.last_refill.elapsed() > ttl
  }
  pub fn avaliable_tokens(&self) -> u32 {
    self.tokens as u32
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::thread::sleep;

  #[test]
  fn fresh_bucket_allows_burst() {
    let mut b = TokenBucket::new(10, 10);
    for _ in 0..10 {
      assert!(b.try_consume().is_ok());
    }
  }

  #[test]
  fn empty_bucket_is_denied() {
    let mut b = TokenBucket::new(1, 1);
    assert!(b.try_consume().is_ok()); // consumes the 1 token
    assert!(b.try_consume().is_err()); // bucket empty
  }

  #[test]
  fn refill_restores_tokens() {
    let mut b = TokenBucket::new(10, 100); // 100 rps = 1 token per 10ms
                                           // Drain the bucket
    for _ in 0..10 {
      let _ = b.try_consume();
    }
    assert!(b.try_consume().is_err()); // empty

    // Wait for ~1 token to refill (100 rps = 10ms per token)
    sleep(Duration::from_millis(15));
    assert!(b.try_consume().is_ok()); // refilled
  }

  #[test]
  fn retry_after_is_positive() {
    let mut b = TokenBucket::new(1, 1); // 1 rps
    let _ = b.try_consume();
    let err = b.try_consume().unwrap_err();
    assert!(err >= 1, "retry_after must be at least 1 second");
  }
}
