use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use nexus_common::{BlockCode, Decision, InnerLayer, RequestContext, Result};
use nexus_config::{PipelineConfig, PolicyConfig};
use nexus_telemetry::PolicyTelemetry;
use tokio::sync::mpsc;
use tonic::transport::{Channel, Endpoint};
use tracing::{debug, warn};

use crate::proto::policy_service_client::PolicyServiceClient;
use crate::proto::{PolicyEvent as ProtoPolicyEvent, PolicyEventBatch, PolicyRequest};

pub mod proto;

use crate::circuit_breaker::CircuitBreaker;

mod circuit_breaker;

const FEEDBACK_CHANNEL_CAPACITY: usize = 10_000;
const DEFAULT_BODY_EXCERPT_BYTES: usize = 512;

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
}

#[derive(Clone)]
pub struct PolicyClient {
  endpoint: String,
  timeout: Duration,
  channel: Channel,
  breaker: Arc<CircuitBreaker>,
}

impl PolicyClient {
  pub fn new(endpoint: String, timeout_ms: u64) -> Self {
    let timeout = Duration::from_millis(timeout_ms);
    let channel = Endpoint::from_shared(endpoint.clone())
      .expect("valid policy.endpoint")
      .connect_timeout(timeout)
      .timeout(timeout)
      .connect_lazy();

    Self {
      endpoint,
      timeout,
      channel,
      breaker: CircuitBreaker::new(5, Duration::from_secs(30)),
    }
  }

  pub fn from_config(cfg: &PolicyConfig) -> Self {
    Self::new(cfg.endpoint.clone(), cfg.timeout_ms)
  }

  pub fn endpoint(&self) -> &str {
    &self.endpoint
  }

  pub async fn decide(
    &self,
    ctx: &RequestContext,
    features: &[f32],
  ) -> std::result::Result<PolicyDecision, String> {
    if self.breaker.is_open() {
      return Err("policy circuit open".to_string());
    }

    let start = Instant::now();
    let request = PolicyRequest {
      request_id: ctx.id.to_string(),
      features: features.to_vec(),
      client_ip: ctx.client_ip.to_string(),
      method: ctx.method.0.as_str().to_string(),
      uri: ctx.uri.clone(),
      threat_tags: sorted_threat_tags(ctx),
      risk_score: ctx.risk_score,
      meta: ctx.meta.clone(),
    };

    let mut client = PolicyServiceClient::new(self.channel.clone());
    let resp = tokio::time::timeout(self.timeout, client.decide(tonic::Request::new(request)))
      .await
      .map_err(|_| "policy timeout".to_string())?
      .map_err(|e| e.to_string())?;

    let payload = resp.into_inner();
    let action = PolicyAction::from_id(payload.action_id)
      .ok_or_else(|| "unknown policy action".to_string())?;

    Ok(PolicyDecision {
      action,
      action_id: payload.action_id,
      action_name: payload.action_name,
      confidence: payload.confidence,
      duration: start.elapsed(),
    })
  }

  pub async fn report_events(
    &self,
    events: Vec<PolicyFeedbackEvent>,
  ) -> std::result::Result<crate::proto::PolicyEventAck, String> {
    if events.is_empty() {
      return Ok(crate::proto::PolicyEventAck {
        accepted: 0,
        feedback_events_total: 0,
        replay_size: 0,
        last_loss: 0.0,
        trained: false,
      });
    }

    let mut client = PolicyServiceClient::new(self.channel.clone());
    let request = PolicyEventBatch {
      events: events.into_iter().map(PolicyFeedbackEvent::into_proto).collect(),
    };

    let response =
      tokio::time::timeout(self.timeout, client.report_events(tonic::Request::new(request)))
        .await
        .map_err(|_| "policy feedback timeout".to_string())?
        .map_err(|e| e.to_string())?;

    Ok(response.into_inner())
  }
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

  async fn init(&self) -> Result<()> {
    tracing::info!(
      endpoint = %self.client.endpoint(),
      enabled = self.config.enabled,
      "Policy layer initialised"
    );
    Ok(())
  }

  async fn analyse(&self, ctx: &mut RequestContext) -> Result<Decision> {
    if !self.config.enabled {
      return Ok(Decision::Allow);
    }

    let features = build_feature_vector(ctx, &self.telemetry, self.config.latency_budget_ms);
    ctx
      .meta
      .insert("policy_features".into(), serialise_feature_vector(&features));

    let decision = match self.client.decide(ctx, &features).await {
      Ok(decision) => {
        self.client.breaker.record_success();
        decision
      }
      Err(error) => {
        self.client.breaker.record_failure();
        if error.contains("circuit open") {
          debug!(
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
        ctx.meta.insert("policy_fallback".into(), "true".into());
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
    ctx.meta.insert(
      "policy_duration_ms".into(),
      format!("{:.3}", decision.duration.as_secs_f64() * 1_000.0),
    );

    Ok(self.apply_action(ctx, decision.action))
  }
}

impl PolicyLayer {
  fn apply_action(&self, ctx: &mut RequestContext, action: PolicyAction) -> Decision {
    match action {
      PolicyAction::AllowNoMl => {
        stamp_effective_action(ctx, PolicyAction::AllowNoMl);
        ctx.meta.insert("skip_ml".into(), "true".into());
        Decision::Allow
      }
      PolicyAction::InvokeMl => {
        stamp_effective_action(ctx, PolicyAction::InvokeMl);
        ctx.meta.insert("skip_ml".into(), "false".into());
        Decision::Allow
      }
      PolicyAction::BlockImmediate => {
        stamp_effective_action(ctx, PolicyAction::BlockImmediate);
        Decision::block("Policy decision: block immediately", BlockCode::MlDetectedThreat)
      }
      PolicyAction::LogAllow => {
        stamp_effective_action(ctx, PolicyAction::LogAllow);
        ctx.tag("policy_log", self.name());
        ctx.meta.insert("skip_ml".into(), "true".into());
        Decision::Log {
          reason: "Policy decision: log and allow".into(),
        }
      }
      PolicyAction::RaiseThreshold => {
        stamp_effective_action(ctx, PolicyAction::RaiseThreshold);
        adjust_threshold(ctx, self.base_risk_threshold, self.config.threshold_step);
        ctx
          .meta
          .insert("risk_threshold_source".into(), self.name().into());
        Decision::Allow
      }
      PolicyAction::LowerThreshold => {
        stamp_effective_action(ctx, PolicyAction::LowerThreshold);
        adjust_threshold(ctx, self.base_risk_threshold, -self.config.threshold_step);
        ctx
          .meta
          .insert("risk_threshold_source".into(), self.name().into());
        Decision::Allow
      }
      PolicyAction::RateLimit => {
        if self.config.allow_rate_limit_action {
          stamp_effective_action(ctx, PolicyAction::RateLimit);
          ctx.rate_limited = true;
          Decision::RateLimit {
            retry_after_seconds: self.config.rate_limit_seconds,
          }
        } else {
          stamp_effective_action(ctx, PolicyAction::AllowNoMl);
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

#[derive(Debug, Clone)]
pub struct PolicyFeedbackEvent {
  pub request_id: String,
  pub unix_time_ms: i64,
  pub features: Vec<f32>,
  pub policy_action_id: i32,
  pub policy_action_name: String,
  pub policy_confidence: f32,
  pub final_decision: String,
  pub decided_by: String,
  pub final_risk_score: f32,
  pub threat_tags: Vec<String>,
  pub block_code: String,
  pub ml_label: String,
  pub ml_score: f32,
  pub has_ml_score: bool,
  pub rate_limited: bool,
  pub method: String,
  pub uri: String,
  pub client_ip: String,
  pub content_type: String,
  pub body_excerpt: String,
  pub meta: HashMap<String, String>,
}

impl PolicyFeedbackEvent {
  pub fn from_context(
    ctx: &RequestContext,
    decision: &Decision,
    decided_by: Option<&str>,
    final_risk_score: f32,
  ) -> Option<Self> {
    let features = parse_feature_vector(ctx.meta.get("policy_features")?)?;
    let policy_action_id = ctx
      .meta
      .get("policy_effective_action_id")
      .or_else(|| ctx.meta.get("policy_action_id"))?
      .parse()
      .ok()?;
    let policy_action_name = ctx
      .meta
      .get("policy_effective_action")
      .or_else(|| ctx.meta.get("policy_action"))?
      .clone();
    let policy_confidence = ctx
      .meta
      .get("policy_confidence")
      .and_then(|value| value.parse::<f32>().ok())
      .unwrap_or(0.0);

    let (final_decision, block_code) = match decision {
      Decision::Allow => ("allow".to_string(), String::new()),
      Decision::Log { .. } => ("log".to_string(), String::new()),
      Decision::RateLimit { .. } => ("rate_limit".to_string(), String::new()),
      Decision::Block { code, .. } => ("block".to_string(), format!("{code:?}")),
    };

    let mut threat_tags: Vec<String> = ctx.threat_tags.iter().cloned().collect();
    threat_tags.sort();

    Some(Self {
      request_id: ctx.id.to_string(),
      unix_time_ms: ctx.recieved_at.timestamp_millis(),
      features,
      policy_action_id,
      policy_action_name,
      policy_confidence,
      final_decision,
      decided_by: decided_by.unwrap_or_default().to_string(),
      final_risk_score,
      threat_tags,
      block_code,
      ml_label: ctx.ml_label.clone().unwrap_or_default(),
      ml_score: ctx.ml_score.unwrap_or_default(),
      has_ml_score: ctx.ml_score.is_some(),
      rate_limited: matches!(decision, Decision::RateLimit { .. }) || ctx.rate_limited,
      method: ctx.method.0.as_str().to_string(),
      uri: ctx.uri.clone(),
      client_ip: ctx.client_ip.to_string(),
      content_type: content_type_name(ctx),
      body_excerpt: body_excerpt(ctx, DEFAULT_BODY_EXCERPT_BYTES),
      meta: ctx.meta.clone(),
    })
  }

  fn into_proto(self) -> ProtoPolicyEvent {
    ProtoPolicyEvent {
      request_id: self.request_id,
      unix_time_ms: self.unix_time_ms,
      features: self.features,
      policy_action_id: self.policy_action_id,
      policy_action_name: self.policy_action_name,
      policy_confidence: self.policy_confidence,
      final_decision: self.final_decision,
      decided_by: self.decided_by,
      final_risk_score: self.final_risk_score,
      threat_tags: self.threat_tags,
      block_code: self.block_code,
      ml_label: self.ml_label,
      ml_score: self.ml_score,
      has_ml_score: self.has_ml_score,
      rate_limited: self.rate_limited,
      method: self.method,
      uri: self.uri,
      client_ip: self.client_ip,
      content_type: self.content_type,
      body_excerpt: self.body_excerpt,
      meta: self.meta,
    }
  }
}

pub struct PolicyFeedbackWriter {
  tx: mpsc::Sender<PolicyFeedbackEvent>,
}

impl PolicyFeedbackWriter {
  pub fn from_config(cfg: &PolicyConfig) -> Self {
    Self::new(
      Arc::new(PolicyClient::from_config(cfg)),
      cfg.feedback_batch_size.max(1),
      cfg.feedback_flush_ms.max(1),
    )
  }

  pub fn new(client: Arc<PolicyClient>, batch_size: usize, flush_ms: u64) -> Self {
    let (tx, mut rx) = mpsc::channel::<PolicyFeedbackEvent>(FEEDBACK_CHANNEL_CAPACITY);

    tokio::spawn(async move {
      let mut batch = Vec::with_capacity(batch_size);
      let mut interval = tokio::time::interval(Duration::from_millis(flush_ms));
      interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

      loop {
        tokio::select! {
          event = rx.recv() => {
            match event {
              Some(event) => {
                batch.push(event);
                if batch.len() >= batch_size {
                  flush_feedback_batch(client.as_ref(), &mut batch).await;
                }
              }
              None => {
                if !batch.is_empty() {
                  flush_feedback_batch(client.as_ref(), &mut batch).await;
                }
                break;
              }
            }
          }
          _ = interval.tick() => {
            if !batch.is_empty() {
              flush_feedback_batch(client.as_ref(), &mut batch).await;
            }
          }
        }
      }
    });

    Self { tx }
  }

  pub fn record(&self, event: PolicyFeedbackEvent) {
    if self.tx.try_send(event).is_err() {
      warn!("PolicyFeedbackWriter channel full or closed - dropping event");
    }
  }
}

async fn flush_feedback_batch(client: &PolicyClient, batch: &mut Vec<PolicyFeedbackEvent>) {
  if batch.is_empty() {
    return;
  }

  let pending = std::mem::take(batch);
  let count = pending.len();
  match client.report_events(pending).await {
    Ok(ack) => {
      debug!(
        accepted = ack.accepted,
        feedback_events_total = ack.feedback_events_total,
        replay_size = ack.replay_size,
        trained = ack.trained,
        last_loss = ack.last_loss,
        "Policy feedback batch flushed"
      );
    }
    Err(error) => {
      warn!(error = %error, count, "Policy feedback batch flush failed - batch dropped");
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

fn stamp_effective_action(ctx: &mut RequestContext, action: PolicyAction) {
  let (id, name) = match action {
    PolicyAction::AllowNoMl => (0, "allow_no_ml"),
    PolicyAction::InvokeMl => (1, "invoke_ml"),
    PolicyAction::BlockImmediate => (2, "block_immediate"),
    PolicyAction::LogAllow => (3, "log_and_allow"),
    PolicyAction::RaiseThreshold => (4, "raise_threshold"),
    PolicyAction::LowerThreshold => (5, "lower_threshold"),
    PolicyAction::RateLimit => (6, "rate_limit_ip"),
  };
  ctx
    .meta
    .insert("policy_effective_action_id".into(), id.to_string());
  ctx
    .meta
    .insert("policy_effective_action".into(), name.to_string());
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
    Some(ContentType::Xml) => 4.0,
    Some(ContentType::PlainText) => 5.0,
    Some(ContentType::Other(_)) => 0.0,
  };
  raw / 5.0
}

fn content_type_name(ctx: &RequestContext) -> String {
  use nexus_common::ContentType;
  match ctx.content_type.as_ref() {
    None => String::new(),
    Some(ContentType::Json) => "json".into(),
    Some(ContentType::FormUrlEncoded) => "form_urlencoded".into(),
    Some(ContentType::Multipart) => "multipart".into(),
    Some(ContentType::Xml) => "xml".into(),
    Some(ContentType::PlainText) => "plain_text".into(),
    Some(ContentType::Other(value)) => value.clone(),
  }
}

fn sorted_threat_tags(ctx: &RequestContext) -> Vec<String> {
  let mut tags: Vec<String> = ctx.threat_tags.iter().cloned().collect();
  tags.sort();
  tags
}

fn serialise_feature_vector(features: &[f32]) -> String {
  features
    .iter()
    .map(|value| format!("{value:.6}"))
    .collect::<Vec<_>>()
    .join(",")
}

fn parse_feature_vector(raw: &str) -> Option<Vec<f32>> {
  let values = raw
    .split(',')
    .map(str::trim)
    .filter(|value| !value.is_empty())
    .map(|value| value.parse::<f32>().ok())
    .collect::<Option<Vec<_>>>()?;

  if values.is_empty() {
    None
  } else {
    Some(values)
  }
}

fn body_excerpt(ctx: &RequestContext, max_bytes: usize) -> String {
  let excerpt_len = ctx.body.len().min(max_bytes);
  String::from_utf8_lossy(&ctx.body[..excerpt_len]).to_string()
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

  #[test]
  fn feature_vector_round_trip_survives_serialisation() {
    let values = vec![0.1, 0.2, 0.3, 1.0];
    let raw = serialise_feature_vector(&values);
    let parsed = parse_feature_vector(&raw).unwrap();
    assert_eq!(parsed.len(), values.len());
    assert!((parsed[2] - values[2]).abs() < 0.0001);
  }

  #[test]
  fn feedback_event_requires_policy_metadata() {
    let ctx = make_ctx();
    let decision = Decision::Allow;
    assert!(PolicyFeedbackEvent::from_context(&ctx, &decision, None, 0.0).is_none());
  }

  #[test]
  fn feedback_event_builds_from_policy_context() {
    let mut ctx = make_ctx();
    ctx.meta.insert("policy_features".into(), "0.1,0.2,0.3".into());
    ctx.meta.insert("policy_action_id".into(), "2".into());
    ctx.meta.insert("policy_action".into(), "block_immediate".into());
    ctx.meta.insert("policy_confidence".into(), "0.91".into());
    ctx.tag("sqli", "lexical");
    ctx.ml_score = Some(0.97);
    ctx.ml_label = Some("threat".into());

    let event = PolicyFeedbackEvent::from_context(
      &ctx,
      &Decision::block("blocked", BlockCode::SqlInjection),
      Some("policy"),
      0.8,
    )
    .unwrap();

    assert_eq!(event.policy_action_id, 2);
    assert_eq!(event.final_decision, "block");
    assert_eq!(event.decided_by, "policy");
    assert!(event.has_ml_score);
    assert_eq!(event.block_code, "SqlInjection");
  }
}
