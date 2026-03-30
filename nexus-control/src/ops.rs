use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration as StdDuration;

use anyhow::{bail, Context};
use chrono::{DateTime, Duration, Utc};
use nexus_lb::UpstreamStatus;
use nexus_policy::proto::policy_service_client::PolicyServiceClient;
use nexus_policy::proto::{
  HealthRequest as PolicyHealthRequest, ListFeedbackEventsRequest, TrainPolicyRequest,
};
use nexus_rules::{Condition, Rule, RuleAction, RuleSet};
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

use crate::stats::{
  AttackLogEntry, ConfigLogEntry, ConfigSnapshot, GpsCandidateView, HealthSnapshot,
  ManualTrainBody, ManualTrainResponse, PaginatedLogs, PolicyEventsQuery,
  PolicyFeedbackEntry, PolicyFeedbackPayload, PolicyServiceSnapshot, RuleVersionView,
  RulesPayload, StatsSnapshot, SynthesizeRulesBody, SynthesizeRulesResponse,
  UpstreamStatusView,
};
use crate::ControlAppState;

#[derive(Debug, Clone, serde::Deserialize)]
pub struct LogsQuery {
  pub page: Option<i64>,
  pub limit: Option<i64>,
  pub from: Option<String>,
  pub to: Option<String>,
  pub ip: Option<String>,
  pub decision: Option<String>,
}

pub fn health_snapshot(state: &Arc<ControlAppState>) -> HealthSnapshot {
  HealthSnapshot {
    ok: true,
    status: "healthy",
    config_version: state.config_version.load(Ordering::Relaxed),
  }
}

pub fn stats_snapshot(state: &Arc<ControlAppState>) -> StatsSnapshot {
  let pipeline = state.pipeline.read();
  let layer_names = pipeline.layer_names();
  drop(pipeline);

  let cfg = state.live_config.borrow().clone();
  let lb = state.load_balancer.read().clone();
  let status_map: HashMap<String, UpstreamStatus> =
    lb.statuses().into_iter().collect();

  let upstreams: Vec<UpstreamStatusView> = cfg
    .lb
    .upstreams
    .iter()
    .map(|u| {
      let status = if !u.enabled {
        "disabled".to_string()
      } else {
        match status_map.get(&u.addr) {
          Some(UpstreamStatus::Healthy) => "healthy".to_string(),
          Some(UpstreamStatus::Unhealthy) => "unhealthy".to_string(),
          Some(UpstreamStatus::Unknown) => "unknown".to_string(),
          None => "unknown".to_string(),
        }
      };

      UpstreamStatusView {
        name: u.name.clone(),
        addr: u.addr.clone(),
        status,
        enabled: u.enabled,
      }
    })
    .collect();

  let healthy_upstreams = upstreams
    .iter()
    .filter(|u| u.status == "healthy")
    .count();

  StatsSnapshot {
    requests_total: state.requests_total.load(Ordering::Relaxed),
    blocked_total: state.blocked_total.load(Ordering::Relaxed),
    rate_limited_total: state.rate_limited_total.load(Ordering::Relaxed),
    pipeline_layers: layer_names,
    config_version: state.config_version.load(Ordering::Relaxed),
    ml_circuit_state: if cfg.pipeline.ml_enabled {
      "enabled".to_string()
    } else {
      "disabled".to_string()
    },
    healthy_upstreams,
    upstreams,
  }
}

pub fn config_snapshot(state: &Arc<ControlAppState>) -> ConfigSnapshot {
  let cfg = state.live_config.borrow().clone();
  ConfigSnapshot {
    version: state.config_version.load(Ordering::Relaxed),
    config: sanitize_config(&cfg),
  }
}

pub fn list_config_logs(state: &Arc<ControlAppState>) -> Vec<ConfigLogEntry> {
  state.config_log.read().clone()
}

pub async fn policy_service_snapshot(
  state: &Arc<ControlAppState>,
) -> anyhow::Result<PolicyServiceSnapshot> {
  let cfg = state.live_config.borrow().clone();

  if !cfg.policy.enabled {
    return Ok(PolicyServiceSnapshot {
      enabled: false,
      endpoint: cfg.policy.endpoint.clone(),
      status: "disabled".to_string(),
      model: String::new(),
      feedback_events_total: 0,
      replay_size: 0,
      last_loss: 0.0,
      online_training_enabled: false,
    });
  }

  match connect_policy_client(&cfg.policy.endpoint, cfg.policy.timeout_ms).await {
    Ok(mut client) => {
      let response = tokio::time::timeout(
        StdDuration::from_millis(cfg.policy.timeout_ms),
        client.health(tonic::Request::new(PolicyHealthRequest {})),
      )
      .await
      .context("policy health timeout")?
      .context("policy health request failed")?
      .into_inner();

      Ok(PolicyServiceSnapshot {
        enabled: true,
        endpoint: cfg.policy.endpoint.clone(),
        status: if response.ready {
          "healthy".to_string()
        } else {
          "starting".to_string()
        },
        model: response.model,
        feedback_events_total: response.feedback_events_total,
        replay_size: response.replay_size,
        last_loss: response.last_loss,
        online_training_enabled: response.online_training_enabled,
      })
    }
    Err(error) => Ok(PolicyServiceSnapshot {
      enabled: true,
      endpoint: cfg.policy.endpoint.clone(),
      status: format!("unreachable: {}", error),
      model: String::new(),
      feedback_events_total: 0,
      replay_size: 0,
      last_loss: 0.0,
      online_training_enabled: false,
    }),
  }
}

pub async fn list_policy_feedback_events(
  state: &Arc<ControlAppState>,
  query: PolicyEventsQuery,
) -> anyhow::Result<PolicyFeedbackPayload> {
  let cfg = state.live_config.borrow().clone();
  if !cfg.policy.enabled {
    return Ok(PolicyFeedbackPayload { events: Vec::new() });
  }

  let limit = query.limit.unwrap_or(25).clamp(1, 200);
  let mut client = match connect_policy_client(&cfg.policy.endpoint, cfg.policy.timeout_ms).await {
    Ok(client) => client,
    Err(error) => {
      tracing::warn!(error = %error, "policy feedback listing unavailable");
      return Ok(PolicyFeedbackPayload { events: Vec::new() });
    }
  };
  let response = match tokio::time::timeout(
    StdDuration::from_millis(cfg.policy.timeout_ms),
    client.list_feedback_events(tonic::Request::new(ListFeedbackEventsRequest { limit })),
  )
  .await
  {
    Ok(Ok(response)) => response.into_inner(),
    Ok(Err(error)) => {
      tracing::warn!(error = %error, "policy feedback listing failed");
      return Ok(PolicyFeedbackPayload { events: Vec::new() });
    }
    Err(error) => {
      tracing::warn!(error = %error, "policy feedback listing timed out");
      return Ok(PolicyFeedbackPayload { events: Vec::new() });
    }
  };

  Ok(PolicyFeedbackPayload {
    events: response
      .events
      .into_iter()
      .map(|event| PolicyFeedbackEntry {
        request_id: event.request_id,
        unix_time_ms: event.unix_time_ms,
        policy_action_name: event.policy_action_name,
        final_decision: event.final_decision,
        decided_by: event.decided_by,
        reward: event.reward,
        method: event.method,
        uri: event.uri,
        block_code: event.block_code,
        rate_limited: event.rate_limited,
      })
      .collect(),
  })
}

pub async fn manual_train_policy(
  state: &Arc<ControlAppState>,
  body: ManualTrainBody,
) -> anyhow::Result<ManualTrainResponse> {
  let cfg = state.live_config.borrow().clone();
  if !cfg.policy.enabled {
    bail!("policy service is disabled in config");
  }

  let mut client = connect_policy_client(&cfg.policy.endpoint, cfg.policy.timeout_ms).await?;
  let response = tokio::time::timeout(
    StdDuration::from_millis(cfg.policy.timeout_ms.max(5_000)),
    client.train_policy(tonic::Request::new(TrainPolicyRequest {
      gradient_updates: body.gradient_updates.unwrap_or(25).max(1),
      replay_from_log_limit: body.replay_from_log_limit.unwrap_or(500),
    })),
  )
  .await
  .context("manual policy training timeout")?
  .context("manual policy training failed")?
  .into_inner();

  Ok(ManualTrainResponse {
    accepted: response.accepted,
    message: response.message,
    updates_run: response.updates_run,
    replay_size: response.replay_size,
    last_loss: response.last_loss,
    checkpoint_saved: response.checkpoint_saved,
  })
}

pub async fn get_rules(state: &Arc<ControlAppState>) -> anyhow::Result<RulesPayload> {
  if let Some(store) = &state.store {
    let rules = store.rules().load_active().await?;
    if let Some(content) = rules {
      let version = extract_rules_version(&content);
      return Ok(RulesPayload {
        found: true,
        version,
        content,
        source: "postgres".to_string(),
      });
    }
  }

  let cfg = state.live_config.borrow().clone();
  let content = tokio::fs::read_to_string(&cfg.rules.rules_file)
    .await
    .unwrap_or_default();
  let found = !content.is_empty();
  Ok(RulesPayload {
    found,
    version: extract_rules_version(&content),
    content,
    source: "file".to_string(),
  })
}

pub async fn update_rules(
  state: &Arc<ControlAppState>,
  version: &str,
  content: &str,
) -> anyhow::Result<u64> {
  let parsed = validate_rules_content(version, content)?;
  apply_rules_content(state, parsed, content).await
}

async fn connect_policy_client(
  endpoint: &str,
  timeout_ms: u64,
) -> anyhow::Result<PolicyServiceClient<tonic::transport::Channel>> {
  let client = tokio::time::timeout(
    StdDuration::from_millis(timeout_ms.max(500)),
    PolicyServiceClient::connect(endpoint.to_string()),
  )
  .await
  .context("policy connect timeout")?
  .context("policy connect failed")?;
  Ok(client)
}

pub async fn synthesize_rules(
  state: &Arc<ControlAppState>,
  body: SynthesizeRulesBody,
) -> anyhow::Result<SynthesizeRulesResponse> {
  let cfg = state.live_config.borrow().clone();
  if !cfg.gps.enabled {
    bail!("GPS synthesis is disabled in config");
  }

  let Some(store) = &state.store else {
    bail!("GPS synthesis requires PostgreSQL-backed attack logs");
  };

  let lookback_hours = body
    .lookback_hours
    .unwrap_or(cfg.gps.default_lookback_hours)
    .max(1);
  let min_hits = body.min_hits.unwrap_or(cfg.gps.min_hits).max(1);
  let max_rules = body.max_rules.unwrap_or(cfg.gps.max_rules).max(1);
  let cutoff = Utc::now() - Duration::hours(lookback_hours);

  let rows = sqlx::query_as::<_, AttackLogEntry>(
    "SELECT id, timestamp, client_ip::text AS client_ip, uri, method, risk_score, decision, \
     threat_tags, blocked_by, ml_score, ml_label, block_code \
     FROM attack_logs WHERE timestamp >= $1 ORDER BY timestamp DESC",
  )
  .bind(cutoff)
  .fetch_all(&store.pg)
  .await
  .context("failed to load attack logs for GPS synthesis")?;

  if rows.is_empty() {
    bail!("no attack logs available in the requested lookback window");
  }

  let current_rules = load_current_rules(state).await?;
  let candidates = build_gps_candidates(&rows, min_hits, max_rules);
  if candidates.is_empty() {
    bail!("no validated candidate rules were synthesized from recent logs");
  }

  let next_version = format!("gps-{}", Utc::now().format("%Y%m%d%H%M%S"));
  let synthesized = append_candidates_to_rules(&current_rules, &next_version, &candidates);
  let content = toml::to_string_pretty(&synthesized).context("failed to serialize GPS rules")?;

  if body.apply {
    let _ = apply_rules_content(state, synthesized.clone(), &content).await?;
  }

  Ok(SynthesizeRulesResponse {
    version: next_version,
    applied: body.apply,
    candidates: candidates.into_iter().map(Into::into).collect(),
    content,
  })
}

fn validate_rules_content(version: &str, content: &str) -> anyhow::Result<RuleSet> {
  if version.trim().is_empty() {
    bail!("rule version must not be empty");
  }
  if content.trim().is_empty() {
    bail!("rule content must not be empty");
  }

  let parsed: RuleSet =
    toml::from_str(content).context("rules content is not valid rules TOML")?;
  if parsed.version.trim().is_empty() {
    bail!("rules TOML must contain a non-empty version");
  }
  if parsed.version != version {
    bail!(
      "request version '{}' does not match TOML version '{}'",
      version,
      parsed.version
    );
  }

  Ok(parsed)
}

async fn apply_rules_content(
  state: &Arc<ControlAppState>,
  parsed: RuleSet,
  content: &str,
) -> anyhow::Result<u64> {
  let cfg = state.live_config.borrow().clone();
  let rules_path = std::path::PathBuf::from(&cfg.rules.rules_file);
  if let Some(parent) = rules_path.parent() {
    tokio::fs::create_dir_all(parent)
      .await
      .with_context(|| format!("failed to create parent directory {}", parent.display()))?;
  }
  tokio::fs::write(&rules_path, content.as_bytes())
    .await
    .with_context(|| format!("failed to write rules file {}", rules_path.display()))?;

  if let Some(store) = &state.store {
    store
      .rules()
      .save(&parsed.version, content)
      .await
      .context("failed to persist rules to PostgreSQL")?;
  }

  let (telemetry, anomaly_state) = {
    let current = state.pipeline.read();
    (current.telemetry(), current.anomaly_state())
  };
  let pipeline = nexus_pipeline::PipelineBuilder::from_config_with_state(
    &cfg,
    telemetry,
    anomaly_state,
  );
  pipeline
    .init()
    .await
    .context("failed to initialize pipeline after rules update")?;
  *state.pipeline.write() = pipeline;

  let new_version = state.config_version.fetch_add(1, Ordering::SeqCst) + 1;
  Ok(new_version)
}

pub async fn list_rule_versions(
  state: &Arc<ControlAppState>,
) -> anyhow::Result<Vec<RuleVersionView>> {
  if let Some(store) = &state.store {
    let versions = store
      .rules()
      .list_versions()
      .await?
      .into_iter()
      .map(Into::into)
      .collect();
    return Ok(versions);
  }

  let cfg = state.live_config.borrow().clone();
  let content = tokio::fs::read_to_string(&cfg.rules.rules_file)
    .await
    .unwrap_or_default();
  if content.is_empty() {
    return Ok(Vec::new());
  }

  Ok(vec![RuleVersionView {
    id: 0,
    version: extract_rules_version(&content),
    created_at: Utc::now(),
    active: true,
  }])
}

pub async fn list_logs(
  state: &Arc<ControlAppState>,
  query: LogsQuery,
) -> anyhow::Result<PaginatedLogs> {
  let page = query.page.unwrap_or(1).max(1);
  let limit = query.limit.unwrap_or(50).clamp(1, 500);
  let offset = (page - 1) * limit;

  let Some(store) = &state.store else {
    return Ok(PaginatedLogs {
      page,
      limit,
      items: Vec::new(),
    });
  };

  let parsed_from = parse_timestamp(query.from.as_deref())?;
  let parsed_to = parse_timestamp(query.to.as_deref())?;

  let mut qb = QueryBuilder::<Postgres>::new(
    "SELECT id, timestamp, client_ip::text AS client_ip, uri, method, risk_score, decision, \
     threat_tags, blocked_by, ml_score, ml_label, block_code FROM attack_logs WHERE 1=1",
  );
  if let Some(from) = parsed_from {
    qb.push(" AND timestamp >= ").push_bind(from);
  }
  if let Some(to) = parsed_to {
    qb.push(" AND timestamp <= ").push_bind(to);
  }
  if let Some(ip) = query.ip.filter(|v| !v.trim().is_empty()) {
    qb.push(" AND client_ip = CAST(")
      .push_bind(ip)
      .push(" AS INET)");
  }
  if let Some(decision) = query.decision.filter(|v| !v.trim().is_empty()) {
    qb.push(" AND decision = ").push_bind(decision);
  }

  qb.push(" ORDER BY timestamp DESC LIMIT ")
    .push_bind(limit)
    .push(" OFFSET ")
    .push_bind(offset);

  let items = qb
    .build_query_as::<AttackLogEntry>()
    .fetch_all(&store.pg)
    .await
    .context("failed to query attack logs")?;

  Ok(PaginatedLogs { page, limit, items })
}

pub async fn get_log_detail(
  state: &Arc<ControlAppState>,
  id: Uuid,
) -> anyhow::Result<Option<AttackLogEntry>> {
  let Some(store) = &state.store else {
    return Ok(None);
  };

  let item = sqlx::query_as::<_, AttackLogEntry>(
    "SELECT id, timestamp, client_ip::text AS client_ip, uri, method, risk_score, decision, \
     threat_tags, blocked_by, ml_score, ml_label, block_code \
     FROM attack_logs WHERE id = $1",
  )
  .bind(id)
  .fetch_optional(&store.pg)
  .await
  .context("failed to query attack log detail")?;

  Ok(item)
}

fn extract_rules_version(content: &str) -> String {
  if content.trim().is_empty() {
    return String::new();
  }
  toml::from_str::<toml::Value>(content)
    .ok()
    .and_then(|v| {
      v.get("version")
        .and_then(|v| v.as_str())
        .map(str::to_string)
    })
    .unwrap_or_else(|| "unknown".to_string())
}

async fn load_current_rules(state: &Arc<ControlAppState>) -> anyhow::Result<RuleSet> {
  let payload = get_rules(state).await?;
  if !payload.found || payload.content.trim().is_empty() {
    return Ok(RuleSet {
      version: "1.0.0".to_string(),
      rules: Vec::new(),
    });
  }

  toml::from_str::<RuleSet>(&payload.content)
    .context("failed to parse current rules before GPS synthesis")
}

#[derive(Debug, Clone)]
struct GpsCandidate {
  id: String,
  name: String,
  description: String,
  kind: String,
  signal: String,
  malicious_hits: i64,
  benign_hits: i64,
  rule: Rule,
}

impl From<GpsCandidate> for GpsCandidateView {
  fn from(value: GpsCandidate) -> Self {
    Self {
      id: value.id,
      name: value.name,
      description: value.description,
      kind: value.kind,
      signal: value.signal,
      malicious_hits: value.malicious_hits,
      benign_hits: value.benign_hits,
    }
  }
}

fn build_gps_candidates(
  rows: &[AttackLogEntry],
  min_hits: i64,
  max_rules: usize,
) -> Vec<GpsCandidate> {
  let malicious: Vec<&AttackLogEntry> = rows
    .iter()
    .filter(|row| row.decision != "Allow" || !row.threat_tags.is_empty())
    .collect();
  let benign: Vec<&AttackLogEntry> = rows
    .iter()
    .filter(|row| row.decision == "Allow" && row.threat_tags.is_empty())
    .collect();

  let mut candidates = Vec::new();

  for (signal, regex) in signal_catalog() {
    let malicious_hits = malicious
      .iter()
      .filter(|row| row.uri.to_ascii_lowercase().contains(signal))
      .count() as i64;
    let benign_hits = benign
      .iter()
      .filter(|row| row.uri.to_ascii_lowercase().contains(signal))
      .count() as i64;

    if malicious_hits < min_hits || benign_hits > 0 {
      continue;
    }

    let id = format!("GPS_REGEX_{}", candidates.len() + 1);
    let name = format!("Block synthesized {signal} probes");
    let description = format!(
      "Synthesized from {malicious_hits} recent malicious requests and validated against benign request URIs."
    );
    candidates.push(GpsCandidate {
      id: id.clone(),
      name: name.clone(),
      description: description.clone(),
      kind: "regex_match".to_string(),
      signal: signal.to_string(),
      malicious_hits,
      benign_hits,
      rule: Rule {
        id,
        name,
        enabled: true,
        priority: 35,
        action: RuleAction::Block,
        description,
        condition: Condition::RegexMatch {
          target: "uri".to_string(),
          pattern: regex.to_string(),
        },
      },
    });
  }

  let suspicious_prefixes = malicious_path_prefixes(&rows);
  for prefix in suspicious_prefixes {
    let malicious_hits = rows
      .iter()
      .filter(|row| row.uri_path().starts_with(&prefix) && row.decision != "Allow")
      .count() as i64;
    let benign_hits = rows
      .iter()
      .filter(|row| row.uri_path().starts_with(&prefix) && row.decision == "Allow")
      .count() as i64;

    if malicious_hits < min_hits || benign_hits > 0 {
      continue;
    }

    let id = format!("GPS_PATH_{}", candidates.len() + 1);
    let name = format!("Block synthesized path prefix {prefix}");
    let description = format!(
      "Synthesized from {malicious_hits} recent malicious requests hitting {prefix} with no benign matches."
    );
    candidates.push(GpsCandidate {
      id: id.clone(),
      name: name.clone(),
      description: description.clone(),
      kind: "path_prefix".to_string(),
      signal: prefix.clone(),
      malicious_hits,
      benign_hits,
      rule: Rule {
        id,
        name,
        enabled: true,
        priority: 30,
        action: RuleAction::Block,
        description,
        condition: Condition::PathPrefix { value: prefix },
      },
    });
  }

  candidates.sort_by(|a, b| {
    b.malicious_hits
      .cmp(&a.malicious_hits)
      .then(a.benign_hits.cmp(&b.benign_hits))
  });
  candidates.truncate(max_rules);
  candidates
}

fn append_candidates_to_rules(
  current_rules: &RuleSet,
  version: &str,
  candidates: &[GpsCandidate],
) -> RuleSet {
  let existing_ids: BTreeSet<&str> = current_rules.rules.iter().map(|rule| rule.id.as_str()).collect();
  let mut rules = current_rules.rules.clone();
  for candidate in candidates {
    if !existing_ids.contains(candidate.rule.id.as_str()) {
      rules.push(candidate.rule.clone());
    }
  }
  rules.sort_by_key(|rule| rule.priority);
  RuleSet {
    version: version.to_string(),
    rules,
  }
}

fn signal_catalog() -> &'static [(&'static str, &'static str)] {
  &[
    ("union select", "(?i)\\bunion\\b.{0,30}\\bselect\\b"),
    ("<script", "(?i)<\\s*script\\b"),
    ("javascript:", "(?i)javascript\\s*:"),
    ("../", "(\\.\\./|\\.\\.\\\\)"),
    ("%2e%2e", "(?i)(%2e%2e|%252e%252e)(%2f|%5c|/|\\\\)"),
    ("/etc/passwd", "(?i)/etc/passwd"),
    ("xp_cmdshell", "(?i)\\bxp_cmdshell\\b"),
    ("waitfor delay", "(?i)waitfor\\s+delay"),
    ("pg_sleep", "(?i)\\bpg_sleep\\s*\\("),
    ("${jndi:", "\\$\\{jndi:"),
  ]
}

fn malicious_path_prefixes(rows: &[AttackLogEntry]) -> Vec<String> {
  let mut prefixes = BTreeSet::new();
  for row in rows {
    let path = row.uri_path();
    if matches!(path.as_str(), "/admin" | "/wp-admin" | "/phpmyadmin" | "/.env" | "/cgi-bin") {
      prefixes.insert(path);
    }
  }
  prefixes.into_iter().collect()
}

trait AttackLogExt {
  fn uri_path(&self) -> String;
}

impl AttackLogExt for AttackLogEntry {
  fn uri_path(&self) -> String {
    let after_scheme = self
      .uri
      .split_once("://")
      .map(|(_, rest)| rest)
      .unwrap_or(self.uri.as_str());
    let path_with_query = after_scheme
      .split_once('/')
      .map(|(_, tail)| format!("/{tail}"))
      .unwrap_or_else(|| "/".to_string());
    path_with_query
      .split('?')
      .next()
      .unwrap_or("/")
      .to_string()
  }
}

fn parse_timestamp(value: Option<&str>) -> anyhow::Result<Option<DateTime<Utc>>> {
  let Some(raw) = value else {
    return Ok(None);
  };
  if raw.trim().is_empty() {
    return Ok(None);
  }
  let parsed = DateTime::parse_from_rfc3339(raw)
    .with_context(|| format!("invalid timestamp (expected RFC3339): {raw}"))?;
  Ok(Some(parsed.with_timezone(&Utc)))
}

fn sanitize_config(cfg: &nexus_config::Config) -> nexus_config::Config {
  let mut cfg = cfg.clone();

  if let Some(token) = cfg.gateway.auth_token.as_mut() {
    if !token.trim().is_empty() {
      *token = "redacted".to_string();
    }
  }

  if !cfg.store.influx_token.trim().is_empty() {
    cfg.store.influx_token = "redacted".to_string();
  }
  if !cfg.slack.webhook_url.trim().is_empty() {
    cfg.slack.webhook_url = "redacted".to_string();
  }

  cfg.store.postgres_url = redact_url(&cfg.store.postgres_url);
  cfg
}

fn redact_url(value: &str) -> String {
  let Some(scheme_end) = value.find("://") else {
    return value.to_string();
  };
  let Some(at) = value.find('@') else {
    return value.to_string();
  };
  let creds = &value[(scheme_end + 3)..at];
  let Some(colon) = creds.find(':') else {
    return value.to_string();
  };
  let user = &creds[..colon];
  let scheme = &value[..scheme_end];
  let rest = &value[(at + 1)..];
  format!("{scheme}://{user}:redacted@{rest}")
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::AtomicU64;
  use std::sync::Arc;

  use super::update_rules;
  use crate::ControlAppState;
  use nexus_config::{ConfigLoader, LiveConfig};
  use nexus_lb::LoadBalancer;
  use nexus_pipeline::PipelineBuilder;
  use parking_lot::RwLock;
  use tokio::sync::watch;

  fn build_state(rules_file: &str) -> Arc<ControlAppState> {
    let config = ConfigLoader::from_str(&format!(
      r#"
[gateway]
listen_addr = "0.0.0.0:8080"
control_addr = "0.0.0.0:9090"
rest_addr = "0.0.0.0:9091"
metrics_addr = "0.0.0.0:9092"
pid_file = "nexus.pid"

[pipeline]

[rate]

[lexical]

[lb]
upstreams = [{{ name = "backend-1", addr = "127.0.0.1:3000" }}]

[rules]
rules_file = "{rules_file}"
"#
    ))
    .expect("config should parse");
    let config = Arc::new(config);
    let (_tx, rx): (_, LiveConfig) = watch::channel(Arc::clone(&config));

    let pipeline = PipelineBuilder::from_config(&config);
    let load_balancer = LoadBalancer::from_config(&config.lb);
    let load_balancer = Arc::new(RwLock::new(Arc::clone(&load_balancer)));
    let config_log = Arc::new(RwLock::new(Vec::new()));

    Arc::new(ControlAppState {
      config,
      live_config: rx,
      pipeline: RwLock::new(pipeline),
      load_balancer,
      config_version: Arc::new(AtomicU64::new(1)),
      config_log,
      requests_total: AtomicU64::new(0),
      blocked_total: AtomicU64::new(0),
      rate_limited_total: AtomicU64::new(0),
      store: None,
      log_writer: None,
      admin_token: "test-token".to_string(),
    })
  }

  #[tokio::test]
  async fn update_rules_rejects_invalid_toml() {
    let temp = tempfile::NamedTempFile::new().expect("temp file");
    let rules_file = temp.path().to_string_lossy().replace('\\', "/");
    let state = build_state(&rules_file);

    let result = update_rules(&state, "1.0.0", "not valid toml").await;
    assert!(result.is_err());
  }

  #[tokio::test]
  async fn update_rules_applies_valid_content() {
    let temp = tempfile::NamedTempFile::new().expect("temp file");
    let rules_file = temp.path().to_string_lossy().replace('\\', "/");
    let state = build_state(&rules_file);

    let content = r#"
version = "2.0.0"

[[rules]]
id = "R001"
name = "Block admin"
enabled = true
priority = 10
action = "block"

[rules.condition]
type = "path_prefix"
value = "/admin"
"#;

    let version = update_rules(&state, "2.0.0", content)
      .await
      .expect("rules update should succeed");
    assert_eq!(version, 2);

    let written = tokio::fs::read_to_string(&rules_file)
      .await
      .expect("rules file should be written");
    assert!(written.contains("version = \"2.0.0\""));
  }
}
