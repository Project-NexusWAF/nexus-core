use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;

#[derive(Debug, Clone)]
pub enum CircuitState {
  Closed { consecutive_failures: u32 },
  Open { opened_at: Instant },
  HalfOpen,
}

#[derive(Debug)]
pub struct CircuitBreaker {
  state: Mutex<CircuitState>,
  failure_threshold: u32,
  reset_timeout: Duration,
}

impl CircuitBreaker {
  pub fn new(failure_threshold: u32, reset_timeout: Duration) -> Arc<Self> {
    Arc::new(Self {
      state: Mutex::new(CircuitState::Closed {
        consecutive_failures: 0,
      }),
      failure_threshold,
      reset_timeout,
    })
  }

  pub fn is_open(&self) -> bool {
    let mut state = self.state.lock();
    match &mut *state {
      CircuitState::Open { opened_at } => {
        if opened_at.elapsed() >= self.reset_timeout {
          *state = CircuitState::HalfOpen;
          false
        } else {
          true
        }
      }
      _ => false,
    }
  }

  pub fn record_success(&self) {
    let mut state = self.state.lock();
    match &mut *state {
      CircuitState::Closed {
        consecutive_failures,
      } => {
        *consecutive_failures = 0;
      }
      CircuitState::HalfOpen => {
        *state = CircuitState::Closed {
          consecutive_failures: 0,
        };
      }
      CircuitState::Open { .. } => {}
    }
  }

  pub fn record_failure(&self) {
    let mut state = self.state.lock();
    match &mut *state {
      CircuitState::Closed {
        consecutive_failures,
      } => {
        *consecutive_failures += 1;
        if *consecutive_failures >= self.failure_threshold {
          *state = CircuitState::Open {
            opened_at: Instant::now(),
          };
        }
      }
      CircuitState::HalfOpen => {
        *state = CircuitState::Open {
          opened_at: Instant::now(),
        };
      }
      CircuitState::Open { .. } => {}
    }
  }

  pub fn state_name(&self) -> &'static str {
    let state = self.state.lock();
    match &*state {
      CircuitState::Closed { .. } => "closed",
      CircuitState::Open { .. } => "open",
      CircuitState::HalfOpen => "half_open",
    }
  }
}

#[cfg(test)]
mod tests {
  use super::{CircuitBreaker, CircuitState};
  use std::time::Duration;

  #[test]
  fn new_breaker_starts_closed() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));
    assert_eq!(breaker.state_name(), "closed");
  }

  #[test]
  fn four_failures_still_closed() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));
    for _ in 0..4 {
      breaker.record_failure();
    }
    assert_eq!(breaker.state_name(), "closed");
    assert!(!breaker.is_open());
  }

  #[test]
  fn five_failures_opens_circuit() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));
    for _ in 0..5 {
      breaker.record_failure();
    }
    assert_eq!(breaker.state_name(), "open");
  }

  #[test]
  fn open_is_open_returns_true() {
    let breaker = CircuitBreaker::new(5, Duration::from_secs(30));
    for _ in 0..5 {
      breaker.record_failure();
    }
    assert!(breaker.is_open());
  }

  #[test]
  fn open_after_timeout_transitions_to_half_open() {
    let breaker = CircuitBreaker::new(1, Duration::ZERO);
    breaker.record_failure();
    assert!(!breaker.is_open());
    assert_eq!(breaker.state_name(), "half_open");
  }

  #[test]
  fn half_open_success_closes_circuit() {
    let breaker = CircuitBreaker::new(1, Duration::from_secs(30));
    *breaker.state.lock() = CircuitState::HalfOpen;
    breaker.record_success();
    assert_eq!(breaker.state_name(), "closed");
  }

  #[test]
  fn half_open_failure_reopens_circuit() {
    let breaker = CircuitBreaker::new(1, Duration::from_secs(30));
    *breaker.state.lock() = CircuitState::HalfOpen;
    breaker.record_failure();
    assert_eq!(breaker.state_name(), "open");
    assert!(breaker.is_open());
  }

  #[test]
  fn closed_success_resets_failure_counter() {
    let breaker = CircuitBreaker::new(3, Duration::from_secs(30));
    breaker.record_failure();
    breaker.record_failure();
    breaker.record_success();
    breaker.record_failure();
    breaker.record_failure();
    assert_eq!(breaker.state_name(), "closed");
    breaker.record_failure();
    assert_eq!(breaker.state_name(), "open");
  }
}
