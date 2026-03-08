use std::time::Duration;

use nexus_common::Decision;

#[derive(Debug, Clone)]
pub struct LayerTiming {
  pub name: &'static str,
  pub duration: Duration,
  pub decision: Decision,
}

#[derive(Debug)]
pub struct RunResult {
  pub decision: Decision,
  pub timings: Vec<LayerTiming>,
  pub total_duration: Duration,
  pub decided_by: Option<&'static str>,
  pub final_risk_score: f32,
}

impl RunResult {
  pub fn is_blocked(&self) -> bool {
    self.decision.is_blocking()
  }

  pub fn http_status(&self) -> u16 {
    self.decision.http_status()
  }
}
