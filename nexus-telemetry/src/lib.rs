use std::collections::VecDeque;
use std::time::Duration;

use parking_lot::Mutex;

const ATTACK_WINDOW: usize = 100;
const LATENCY_WINDOW: usize = 200;

#[derive(Debug, Default)]
struct TelemetryState {
  attacks: VecDeque<bool>,
  latencies_ms: VecDeque<f32>,
}

/// Lightweight, shared telemetry for policy decisions.
/// Tracks recent attack rate and p95 latency.
#[derive(Debug, Default)]
pub struct PolicyTelemetry {
  state: Mutex<TelemetryState>,
}

impl PolicyTelemetry {
  pub fn new() -> Self {
    Self {
      state: Mutex::new(TelemetryState::default()),
    }
  }

  pub fn record_outcome(&self, is_attack: bool, duration: Duration) {
    let mut state = self.state.lock();
    if state.attacks.len() >= ATTACK_WINDOW {
      state.attacks.pop_front();
    }
    state.attacks.push_back(is_attack);

    let latency_ms = duration.as_secs_f64() * 1000.0;
    if state.latencies_ms.len() >= LATENCY_WINDOW {
      state.latencies_ms.pop_front();
    }
    state.latencies_ms.push_back(latency_ms as f32);
  }

  pub fn recent_attack_rate(&self) -> f32 {
    let state = self.state.lock();
    if state.attacks.is_empty() {
      return 0.0;
    }
    let hits = state.attacks.iter().filter(|v| **v).count();
    (hits as f32 / state.attacks.len() as f32).min(1.0)
  }

  pub fn p95_latency_ms(&self) -> f32 {
    let state = self.state.lock();
    if state.latencies_ms.is_empty() {
      return 0.0;
    }
    let mut vals: Vec<f32> = state.latencies_ms.iter().copied().collect();
    vals.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let idx = ((vals.len() as f32 - 1.0) * 0.95).round() as usize;
    vals[idx.min(vals.len() - 1)]
  }
}

#[cfg(test)]
mod tests {
  use super::PolicyTelemetry;
  use std::time::Duration;

  #[test]
  fn recent_attack_rate_defaults_to_zero() {
    let telemetry = PolicyTelemetry::new();
    assert_eq!(telemetry.recent_attack_rate(), 0.0);
  }

  #[test]
  fn attack_rate_tracks_recent_window() {
    let telemetry = PolicyTelemetry::new();
    telemetry.record_outcome(true, Duration::from_millis(10));
    telemetry.record_outcome(false, Duration::from_millis(12));
    telemetry.record_outcome(true, Duration::from_millis(9));
    let rate = telemetry.recent_attack_rate();
    assert!(rate > 0.0);
    assert!(rate <= 1.0);
  }

  #[test]
  fn p95_latency_returns_latest_quantile() {
    let telemetry = PolicyTelemetry::new();
    for i in 0..20 {
      telemetry.record_outcome(false, Duration::from_millis(10 + i));
    }
    let p95 = telemetry.p95_latency_ms();
    assert!(p95 >= 10.0);
  }
}
