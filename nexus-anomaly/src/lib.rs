use std::collections::VecDeque;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use nexus_common::{BlockCode, Decision, InnerLayer, RequestContext, Result};
use nexus_config::AnomalyConfig;
use parking_lot::Mutex;
use tracing::warn;

#[derive(Debug)]
struct AnomalyStateInner {
  request_times: VecDeque<Instant>,
  ewma_rps: f64,
  var_rps: f64,
  ewma_body: f64,
  var_body: f64,
  ewma_risk: f64,
  var_risk: f64,
  samples: u64,
  last_flag: Option<Instant>,
}

#[derive(Debug)]
pub struct AnomalyState {
  inner: Mutex<AnomalyStateInner>,
}

impl AnomalyState {
  pub fn new() -> Self {
    Self {
      inner: Mutex::new(AnomalyStateInner {
        request_times: VecDeque::new(),
        ewma_rps: 0.0,
        var_rps: 0.0,
        ewma_body: 0.0,
        var_body: 0.0,
        ewma_risk: 0.0,
        var_risk: 0.0,
        samples: 0,
        last_flag: None,
      }),
    }
  }
}

pub struct AnomalyLayer {
  state: std::sync::Arc<AnomalyState>,
  config: AnomalyConfig,
}

impl AnomalyLayer {
  pub fn new(config: AnomalyConfig, state: std::sync::Arc<AnomalyState>) -> Self {
    Self { state, config }
  }

  pub fn from_config(cfg: &AnomalyConfig, state: std::sync::Arc<AnomalyState>) -> Self {
    Self::new(cfg.clone(), state)
  }
}

#[async_trait]
impl InnerLayer for AnomalyLayer {
  fn name(&self) -> &'static str {
    "anomaly"
  }

  fn priority(&self) -> u8 {
    25
  }

  async fn analyse(&self, ctx: &mut RequestContext) -> Result<Decision> {
    if !self.config.enabled {
      return Ok(Decision::Allow);
    }

    let now = Instant::now();
    let mut state = self.state.inner.lock();

    let window = Duration::from_secs(self.config.window_secs.max(1));
    state.request_times.push_back(now);
    while let Some(front) = state.request_times.front() {
      if now.duration_since(*front) > window {
        state.request_times.pop_front();
      } else {
        break;
      }
    }

    let window_secs = window.as_secs_f64();
    let current_rps = if window_secs > 0.0 {
      state.request_times.len() as f64 / window_secs
    } else {
      0.0
    };
    let current_body = ctx.body.len() as f64;
    let current_risk = ctx.risk_score as f64;

    let alpha = self.config.ewma_alpha.clamp(0.01, 1.0) as f64;

    let z_rps = z_score(current_rps, state.ewma_rps, state.var_rps);
    let z_body = z_score(current_body, state.ewma_body, state.var_body);
    let z_risk = z_score(current_risk, state.ewma_risk, state.var_risk);
    let max_z = z_rps.max(z_body).max(z_risk);

    // Update EWMA stats
    let (mean_rps, var_rps) = update_ewma(state.ewma_rps, state.var_rps, current_rps, alpha);
    state.ewma_rps = mean_rps;
    state.var_rps = var_rps;
    let (mean_body, var_body) = update_ewma(state.ewma_body, state.var_body, current_body, alpha);
    state.ewma_body = mean_body;
    state.var_body = var_body;
    let (mean_risk, var_risk) = update_ewma(state.ewma_risk, state.var_risk, current_risk, alpha);
    state.ewma_risk = mean_risk;
    state.var_risk = var_risk;
    state.samples = state.samples.saturating_add(1);

    let in_cooldown = state
      .last_flag
      .is_some_and(|t| now.duration_since(t) < Duration::from_secs(self.config.cooldown_secs));

    if state.samples >= self.config.min_samples && max_z >= self.config.z_score_threshold as f64 && !in_cooldown {
      state.last_flag = Some(now);
      ctx.tag("anomaly", self.name());
      ctx
        .meta
        .insert("anomaly_score".into(), format!("{:.2}", max_z));
      ctx.add_risk(self.config.risk_delta);

      warn!(
        request_id = %ctx.id,
        client_ip = %ctx.client_ip,
        z_score = max_z,
        "Anomaly detected from baseline"
      );

      if self.config.block_on_anomaly {
        return Ok(Decision::block(
          "Anomalous request pattern detected",
          BlockCode::ProtocolViolation,
        ));
      }
    }

    Ok(Decision::Allow)
  }
}

fn z_score(value: f64, mean: f64, var: f64) -> f64 {
  if var <= 1e-6 {
    0.0
  } else {
    (value - mean) / var.sqrt()
  }
}

fn update_ewma(mean: f64, var: f64, value: f64, alpha: f64) -> (f64, f64) {
  let delta = value - mean;
  let mean_next = mean + alpha * delta;
  let var_next = (1.0 - alpha) * (var + alpha * delta * delta);
  (mean_next, var_next)
}

#[cfg(test)]
mod tests {
  use super::*;
  use bytes::Bytes;
  use http::{HeaderMap, Method, Version};
  use std::net::{IpAddr, Ipv4Addr};

  fn make_ctx() -> RequestContext {
    RequestContext::new(
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
      Method::GET,
      "http://example.com/".parse().unwrap(),
      Version::HTTP_11,
      HeaderMap::new(),
      Bytes::new(),
    )
  }

  #[tokio::test]
  async fn anomaly_layer_disabled_allows() {
    let cfg = AnomalyConfig {
      enabled: false,
      ..AnomalyConfig::default()
    };
    let layer = AnomalyLayer::new(cfg, std::sync::Arc::new(AnomalyState::new()));
    let mut ctx = make_ctx();
    let decision = layer.analyse(&mut ctx).await.unwrap();
    assert!(matches!(decision, Decision::Allow));
  }
}
