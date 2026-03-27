use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use nexus_common::{BlockCode, Decision, InnerLayer, RequestContext, Result};
use nexus_config::{PipelineConfig, PolicyConfig};
use nexus_telemetry::PolicyTelemetry;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::circuit_breaker::CircuitBreaker;

mod circuit_breaker;

#[derive(Debug, Clone, Copy)]
pub enum PolicyAction {
  AllowNoMl,
  InvokeMl,
  BlockImmediate,
  LogAllow,
  RaiseThreshold,
  LowerThreshold,
  RateLimit,
}

impl PolicyAction {
  fn from_id(id: i32) -> Option<Self> {
    match id {
      0 => Some(Self::AllowNoMl),
      1 => Some(Self::InvokeMl),
      2 => Some(Self::BlockImmediate),
      3 => Some(Self::LogAllow),
      4 => Some(Self::RaiseThreshold),
      5 => Some(Self::LowerThreshold),
      6 => Some(Self::RateLimit),
      _ => None,
    }
  }
}

#[derive(Debug)]
pub struct PolicyDecision {
  pub action: PolicyAction,
  pub action_id: i32,
  pub action_name: String,
  pub confidence: f32,
  pub duration: Duration,
  pub available: bool,
}

pub struct PolicyClient {
  endpoint: String,
  http: reqwest::Client,
  breaker: Arc<CircuitBreaker>,
}

impl PolicyClient {
  pub fn new(endpoint: String, timeout_ms: u64) -> Self {
    Self {
      endpoint,
      http: reqwest::Client::builder()
        .timeout(Duration::from_millis(timeout_ms))
        .build()
        .expect("policy http client"),
      breaker: CircuitBreaker::new(5, Duration::from_secs(30)),
    }
  }

  pub fn from_config(cfg: &PolicyConfig) -> Self {
    Self::new(cfg.endpoint.clone(), cfg.timeout_ms)
  }

  fn decision_url(&self) -> String {
    if self.endpoint.ends_with("/decide") {
      self.endpoint.clone()
    } else {
      format!("{}/decide", self.endpoint.trim_end_matches('/'))
    }
  }

  pub async fn decide(&self, features: &[f32]) -> std::result::Result<PolicyDecision, String> {
    if self.breaker.is_open() {
      return Err("policy circuit open".to_string());
    }

    let request = PolicyRequest {
      features: features.to_vec(),
    };
    let url = self.decision_url();
    let start = Instant::now();

    let resp = self
      .http
      .post(&url)
      .json(&request)
      .send()
      .await
      .map_err(|e| e.to_string())?;

    if !resp.status().is_success() {
      return Err(format!("policy HTTP {}", resp.status()));
    }

    let payload: PolicyResponse = resp.json().await.map_err(|e| e.to_string())?;
    let action = PolicyAction::from_id(payload.action_id)
      .ok_or_else(|| "unknown policy action".to_string())?;

    Ok(PolicyDecision {
      action,
      action_id: payload.action_id,
      action_name: payload.action_name,
      confidence: payload.confidence,
      duration: start.elapsed(),
      available: true,
    })
  }
}

#[derive(Serialize)]
struct PolicyRequest {
  features: Vec<f32>,
}

#[derive(Deserialize)]
struct PolicyResponse {
  action_id: i32,
  action_name: String,
  confidence: f32,
}

pub struct PolicyLayer {
  client: PolicyClient,
  telemetry: Arc<PolicyTelemetry>,
  config: PolicyConfig,
  base_risk_threshold: f32,
}

impl PolicyLayer {
  pub fn from_config(
    policy_cfg: &PolicyConfig,
    pipeline_cfg: &PipelineConfig,
    telemetry: Arc<PolicyTelemetry>,
  ) -> Self {
    Self {
      client: PolicyClient::from_config(policy_cfg),
      telemetry,
      config: policy_cfg.clone(),
      base_risk_threshold: pipeline_cfg.risk_threshold,
    }
  }
}

#[async_trait]
impl InnerLayer for PolicyLayer {
  fn name(&self) -> &'static str {
    "policy"
  }

  fn priority(&self) -> u8 {
    35
  }

  async fn analyse(&self, ctx: &mut RequestContext) -> Result<Decision> {
    if !self.config.enabled {
      return Ok(Decision::Allow);
    }

    let features = build_feature_vector(ctx, &self.telemetry, self.config.latency_budget_ms);

    let decision = match self.client.decide(&features).await {
      Ok(decision) => {
        self.client.breaker.record_success();
        decision
      }
      Err(error) => {
        self.client.breaker.record_failure();
        if error.contains("circuit open") {
          tracing::debug!(
            request_id = %ctx.id,
            error = %error,
            "Policy circuit open; applying fallback"
          );
        } else {
          warn!(
            request_id = %ctx.id,
            error = %error,
            "Policy service unavailable; applying fallback"
          );
        }
        return Ok(self.apply_fallback(ctx));
      }
    };

    ctx
      .meta
      .insert("policy_action_id".into(), decision.action_id.to_string());
    ctx
      .meta
      .insert("policy_action".into(), decision.action_name.clone());
    ctx
      .meta
      .insert("policy_confidence".into(), format!("{:.3}", decision.confidence));

    Ok(self.apply_action(ctx, decision.action))
  }
}

impl PolicyLayer {
  fn apply_action(&self, ctx: &mut RequestContext, action: PolicyAction) -> Decision {
    match action {
      PolicyAction::AllowNoMl => {
        ctx.meta.insert("skip_ml".into(), "true".into());
        Decision::Allow
      }
      PolicyAction::InvokeMl => {
        ctx.meta.insert("skip_ml".into(), "false".into());
        Decision::Allow
      }
      PolicyAction::BlockImmediate => Decision::block(
        "Policy decision: block immediately",
        BlockCode::MlDetectedThreat,
      ),
      PolicyAction::LogAllow => {
        ctx.tag("policy_log", self.name());
        ctx.meta.insert("skip_ml".into(), "true".into());
        Decision::Log {
          reason: "Policy decision: log and allow".into(),
        }
      }
      PolicyAction::RaiseThreshold => {
        adjust_threshold(ctx, self.base_risk_threshold, self.config.threshold_step);
        ctx
          .meta
          .insert("risk_threshold_source".into(), self.name().into());
        Decision::Allow
      }
      PolicyAction::LowerThreshold => {
        adjust_threshold(ctx, self.base_risk_threshold, -self.config.threshold_step);
        ctx
          .meta
          .insert("risk_threshold_source".into(), self.name().into());
        Decision::Allow
      }
      PolicyAction::RateLimit => {
        if self.config.allow_rate_limit_action {
          ctx.rate_limited = true;
          Decision::RateLimit {
            retry_after_seconds: self.config.rate_limit_seconds,
          }
        } else {
          ctx.meta.insert("skip_ml".into(), "true".into());
          Decision::Allow
        }
      }
    }
  }

  fn apply_fallback(&self, ctx: &mut RequestContext) -> Decision {
    use nexus_config::PolicyFallbackAction;

    match self.config.fallback_action {
      PolicyFallbackAction::AllowNoMl => {
        ctx.meta.insert("skip_ml".into(), "true".into());
        Decision::Allow
      }
      PolicyFallbackAction::InvokeMl => {
        ctx.meta.insert("skip_ml".into(), "false".into());
        Decision::Allow
      }
      PolicyFallbackAction::Auto => {
        let attack_rate = self.telemetry.recent_attack_rate();
        let p95 = self.telemetry.p95_latency_ms();
        if attack_rate >= self.config.attack_rate_threshold
          || p95 >= self.config.latency_budget_ms as f32
        {
          ctx.meta.insert("skip_ml".into(), "true".into());
          Decision::Allow
        } else {
          ctx.meta.insert("skip_ml".into(), "false".into());
          Decision::Allow
        }
      }
    }
  }
}

fn adjust_threshold(ctx: &mut RequestContext, base: f32, delta: f32) {
  let current = ctx
    .meta
    .get("risk_threshold")
    .and_then(|v| v.parse::<f32>().ok())
    .unwrap_or(base);
  let next = (current + delta).clamp(0.0, 1.0);
  ctx.meta
    .insert("risk_threshold".into(), format!("{:.3}", next));
}

fn build_feature_vector(
  ctx: &RequestContext,
  telemetry: &PolicyTelemetry,
  latency_budget_ms: u64,
) -> Vec<f32> {
  let risk_score = ctx.risk_score;
  let tag_count = (ctx.threat_tags.len() as f32 / 5.0).min(1.0);
  let has_sqli = ctx.threat_tags.contains("sqli") as u8 as f32;
  let has_xss = ctx.threat_tags.contains("xss") as u8 as f32;
  let has_traversal = ctx.threat_tags.contains("path_traversal") as u8 as f32;
  let has_cmd = ctx.threat_tags.contains("cmd_injection") as u8 as f32;
  let body_len_norm = (ctx.body.len() as f32 / 8192.0).min(1.0);
  let uri_len_norm = (ctx.uri.len() as f32 / 2048.0).min(1.0);
  let query_norm = (ctx.query_params.len() as f32 / 20.0).min(1.0);
  let rate_limited = ctx.rate_limited as u8 as f32;
  let recent_attack_rate = telemetry.recent_attack_rate();
  let p95_latency = telemetry.p95_latency_ms();
  let latency_norm = if latency_budget_ms == 0 {
    0.0
  } else {
    (p95_latency / latency_budget_ms as f32).min(1.0)
  };
  let has_referer = ctx.headers.0.get("referer").is_some() as u8 as f32;
  let content_type = encode_content_type(ctx).min(1.0);
  let grammar_risk = ctx
    .meta
    .get("grammar_risk")
    .and_then(|v| v.parse::<f32>().ok())
    .unwrap_or(0.0)
    .min(1.0);

  vec![
    risk_score,
    tag_count,
    has_sqli,
    has_xss,
    has_traversal,
    has_cmd,
    body_len_norm,
    uri_len_norm,
    query_norm,
    rate_limited,
    recent_attack_rate,
    latency_norm,
    has_referer,
    content_type,
    grammar_risk,
  ]
}

fn encode_content_type(ctx: &RequestContext) -> f32 {
  use nexus_common::ContentType;
  let raw = match ctx.content_type.as_ref() {
    None => 0.0,
    Some(ContentType::Json) => 1.0,
    Some(ContentType::FormUrlEncoded) => 2.0,
    Some(ContentType::Multipart) => 3.0,
    Some(ContentType::Xml) => 1.0,
    Some(ContentType::PlainText) => 1.0,
    Some(ContentType::Other(_)) => 1.0,
  };
  raw / 3.0
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

  #[test]
  fn feature_vector_length_is_fixed() {
    let ctx = make_ctx();
    let telemetry = PolicyTelemetry::new();
    let vec = build_feature_vector(&ctx, &telemetry, 20);
    assert_eq!(vec.len(), 15);
  }

  #[test]
  fn adjust_threshold_respects_bounds() {
    let mut ctx = make_ctx();
    adjust_threshold(&mut ctx, 0.7, 1.0);
    let value = ctx
      .meta
      .get("risk_threshold")
      .unwrap()
      .parse::<f32>()
      .unwrap();
    assert!(value <= 1.0);
  }
}
