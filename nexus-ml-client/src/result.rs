use std::time::Duration;

#[derive(Debug, Clone)]
pub struct MlResult {
  pub score: f32,
  pub label: String,
  pub available: bool,
  pub duration: Duration,
}

impl MlResult {
  pub fn unavailable(reason: &str, duration: Duration) -> Self {
    let reason = nexus_common::sanitise_for_log(reason, 256);
    tracing::warn!(reason = %reason, "ML inference unavailable, failing open");
    Self {
      score: 0.0,
      label: "unavailable".into(),
      available: false,
      duration,
    }
  }

  pub fn is_threat(&self, threshold: f32) -> bool {
    self.available && self.score > threshold
  }
}

#[cfg(test)]
mod tests {
  use super::MlResult;
  use std::time::Duration;

  #[test]
  fn unavailable_is_never_threat() {
    let result = MlResult::unavailable("t", Duration::ZERO);
    assert!(!result.is_threat(0.0));
  }

  #[test]
  fn available_above_threshold_is_threat() {
    let result = MlResult {
      score: 0.9,
      label: "threat".into(),
      available: true,
      duration: Duration::ZERO,
    };
    assert!(result.is_threat(0.8));
  }

  #[test]
  fn available_at_threshold_is_not_threat() {
    let result = MlResult {
      score: 0.8,
      label: "threat".into(),
      available: true,
      duration: Duration::ZERO,
    };
    assert!(!result.is_threat(0.8));
  }
}
