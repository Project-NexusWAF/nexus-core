use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use nexus_lb::UpstreamStatus;
use sqlx::{Postgres, QueryBuilder};
use uuid::Uuid;

use crate::stats::{
  AttackLogEntry, ConfigLogEntry, ConfigSnapshot, HealthSnapshot, PaginatedLogs, RuleVersionView,
  RulesPayload, StatsSnapshot, UpstreamStatusView,
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
    // Placeholder until ML layer exposes circuit state through public API.
    ml_circuit_state: "unknown".to_string(),
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
  if version.trim().is_empty() {
    bail!("rule version must not be empty");
  }
  if content.trim().is_empty() {
    bail!("rule content must not be empty");
  }

  let parsed: nexus_rules::RuleSet =
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
      .save(version, content)
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
