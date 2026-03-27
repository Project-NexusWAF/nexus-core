use chrono::{DateTime, Utc};
use nexus_config::Config;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct HealthSnapshot {
  pub ok: bool,
  pub status: &'static str,
  pub config_version: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct UpstreamStatusView {
  pub name: String,
  pub addr: String,
  pub status: String,
  pub enabled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct StatsSnapshot {
  pub requests_total: u64,
  pub blocked_total: u64,
  pub rate_limited_total: u64,
  pub pipeline_layers: Vec<&'static str>,
  pub config_version: u64,
  pub ml_circuit_state: String,
  pub healthy_upstreams: usize,
  pub upstreams: Vec<UpstreamStatusView>,
}

#[derive(Debug, Clone, Serialize)]
pub struct RulesPayload {
  pub found: bool,
  pub version: String,
  pub content: String,
  pub source: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct RuleVersionView {
  pub id: i32,
  pub version: String,
  pub created_at: DateTime<Utc>,
  pub active: bool,
}

impl From<nexus_store::RuleSetMeta> for RuleVersionView {
  fn from(value: nexus_store::RuleSetMeta) -> Self {
    Self {
      id: value.id,
      version: value.version,
      created_at: value.created_at,
      active: value.active,
    }
  }
}

#[derive(Debug, Clone, Serialize, sqlx::FromRow)]
pub struct AttackLogEntry {
  pub id: Uuid,
  pub timestamp: DateTime<Utc>,
  pub client_ip: String,
  pub uri: String,
  pub method: String,
  pub risk_score: f32,
  pub decision: String,
  pub threat_tags: Vec<String>,
  pub blocked_by: Option<String>,
  pub ml_score: Option<f32>,
  pub ml_label: Option<String>,
  pub block_code: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct PaginatedLogs {
  pub page: i64,
  pub limit: i64,
  pub items: Vec<AttackLogEntry>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigSnapshot {
  pub version: u64,
  pub config: Config,
}

#[derive(Debug, Clone, Serialize)]
pub struct ConfigLogEntry {
  pub timestamp: DateTime<Utc>,
  pub version: u64,
  pub status: String,
  pub message: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateRulesBody {
  pub version: String,
  pub content: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct SynthesizeRulesBody {
  pub lookback_hours: Option<i64>,
  pub min_hits: Option<i64>,
  pub max_rules: Option<usize>,
  #[serde(default)]
  pub apply: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct GpsCandidateView {
  pub id: String,
  pub name: String,
  pub description: String,
  pub kind: String,
  pub signal: String,
  pub malicious_hits: i64,
  pub benign_hits: i64,
}

#[derive(Debug, Clone, Serialize)]
pub struct SynthesizeRulesResponse {
  pub version: String,
  pub applied: bool,
  pub candidates: Vec<GpsCandidateView>,
  pub content: String,
}
