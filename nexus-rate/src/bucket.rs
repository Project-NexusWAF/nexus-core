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
