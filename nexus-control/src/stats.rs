use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize)]
pub struct HealthSnapshot {
  pub ok: bool,
  pub status: &'static str,
  pub config_version: u64,
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

#[derive(Debug, Clone, Deserialize)]
pub struct UpdateRulesBody {
  pub version: String,
  pub content: String,
}
