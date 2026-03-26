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
}
