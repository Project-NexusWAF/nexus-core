/// Root configuration for the entire nexus-core data plane.
/// Loaded from TOML, with environment variable overrides.
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
  pub gateway: GatewayConfig,
  pub pipeline: PipelineConfig,
  pub rate: RateConfig,
  pub lexical: LexicalConfig,
  pub lb: LbConfig,

  #[serde(default)]
  pub ml: MlConfig,
  #[serde(default)]
  pub policy: PolicyConfig,
  #[serde(default)]
  pub anomaly: AnomalyConfig,
  pub rules: RulesConfig,

  #[serde(default)]
  pub store: StoreConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
  pub listen_addr: String,
  pub control_addr: String,
  #[serde(default = "default_rest_addr")]
  pub rest_addr: String,
  #[serde(default = "default_metrics_addr")]
  pub metrics_addr: String,
  #[serde(default)]
  pub auth_token: Option<String>,
  #[serde(default = "default_pid_file")]
  pub pid_file: String,

  #[serde(default = "default_max_body_bytes")]
  pub max_body_bytes: usize,
  #[serde(default = "default_request_timeout_ms")]
  pub request_timeout_ms: u64,

  #[serde(default)]
  pub worker_threads: usize,

  #[serde(default = "bool_true")]
  pub trust_x_forwarded_for: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PipelineConfig {
  #[serde(default = "default_risk_threshold")]
  pub risk_threshold: f32,

  #[serde(default = "bool_true")]
  pub ml_enabled: bool,

  #[serde(default = "bool_true")]
  pub short_circuit: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateConfig {
  #[serde(default = "bool_true")]
  pub enabled: bool,

  #[serde(default = "default_rps")]
  pub requests_per_second: u32,

  #[serde(default = "default_burst")]
  pub burst_capacity: u32,

  #[serde(default = "default_window_secs")]
  pub window_secs: u64,

  #[serde(default = "default_cleanup_secs")]
  pub cleanup_interval_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LexicalConfig {
  #[serde(default = "bool_true")]
  pub sqli_enabled: bool,

  #[serde(default = "bool_true")]
  pub xss_enabled: bool,

  #[serde(default = "bool_true")]
  pub path_traversal_enabled: bool,

  #[serde(default = "bool_true")]
  pub cmd_injection_enabled: bool,

  #[serde(default = "default_lexical_risk_delta")]
  pub risk_delta: f32,

  #[serde(default)]
  pub block_on_match: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LbConfig {
  #[serde(default)]
  pub algorithm: LbAlgorithm,

  pub upstreams: Vec<UpstreamConfig>,

  #[serde(default = "default_health_check_secs")]
  pub health_check_interval_secs: u64,

  #[serde(default = "default_unhealthy_threshold")]
  pub unhealthy_threshold: u32,

  #[serde(default = "default_healthy_threshold")]
  pub healthy_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum LbAlgorithm {
  #[default]
  RoundRobin,
  WeightedRoundRobin,
  LeastConnections,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
  pub name: String,

  pub addr: String,

  #[serde(default = "default_weight")]
  pub weight: u32,

  #[serde(default = "bool_true")]
  pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MlConfig {
  #[serde(default = "default_ml_endpoint")]
  pub endpoint: String,

  #[serde(default = "default_ml_timeout_ms")]
  pub timeout_ms: u64,

  #[serde(default = "default_ml_risk_delta")]
  pub risk_delta: f32,

  #[serde(default = "default_ml_threshold")]
  pub confidence_threshold: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PolicyFallbackAction {
  AllowNoMl,
  InvokeMl,
  #[default]
  Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
  #[serde(default = "bool_true")]
  pub enabled: bool,
  #[serde(default = "default_policy_endpoint")]
  pub endpoint: String,
  #[serde(default = "default_policy_timeout_ms")]
  pub timeout_ms: u64,
  #[serde(default)]
  pub fallback_action: PolicyFallbackAction,
  #[serde(default = "default_policy_latency_budget_ms")]
  pub latency_budget_ms: u64,
  #[serde(default = "default_policy_threshold_step")]
  pub threshold_step: f32,
  #[serde(default = "default_policy_rate_limit_seconds")]
  pub rate_limit_seconds: u32,
  #[serde(default = "default_policy_attack_rate_threshold")]
  pub attack_rate_threshold: f32,
  #[serde(default = "bool_true")]
  pub allow_rate_limit_action: bool,
}

impl Default for PolicyConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      endpoint: default_policy_endpoint(),
      timeout_ms: default_policy_timeout_ms(),
      fallback_action: PolicyFallbackAction::default(),
      latency_budget_ms: default_policy_latency_budget_ms(),
      threshold_step: default_policy_threshold_step(),
      rate_limit_seconds: default_policy_rate_limit_seconds(),
      attack_rate_threshold: default_policy_attack_rate_threshold(),
      allow_rate_limit_action: true,
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyConfig {
  #[serde(default = "bool_true")]
  pub enabled: bool,
  #[serde(default = "default_anomaly_window_secs")]
  pub window_secs: u64,
  #[serde(default = "default_anomaly_z_threshold")]
  pub z_score_threshold: f32,
  #[serde(default = "default_anomaly_min_samples")]
  pub min_samples: u64,
  #[serde(default = "default_anomaly_risk_delta")]
  pub risk_delta: f32,
  #[serde(default)]
  pub block_on_anomaly: bool,
  #[serde(default = "default_anomaly_ewma_alpha")]
  pub ewma_alpha: f32,
  #[serde(default = "default_anomaly_cooldown_secs")]
  pub cooldown_secs: u64,
}

impl Default for AnomalyConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      window_secs: default_anomaly_window_secs(),
      z_score_threshold: default_anomaly_z_threshold(),
      min_samples: default_anomaly_min_samples(),
      risk_delta: default_anomaly_risk_delta(),
      block_on_anomaly: false,
      ewma_alpha: default_anomaly_ewma_alpha(),
      cooldown_secs: default_anomaly_cooldown_secs(),
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
  pub rules_file: String,

  #[serde(default = "bool_true")]
  pub fail_closed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreConfig {
  #[serde(default = "default_postgres_url")]
  pub postgres_url: String,
  #[serde(default = "default_influx_url")]
  pub influx_url: String,
  #[serde(default)]
  pub influx_token: String,
  #[serde(default = "default_influx_org")]
  pub influx_org: String,
  #[serde(default = "default_influx_bucket")]
  pub influx_bucket: String,
  #[serde(default = "default_batch_size")]
  pub log_batch_size: usize,
  #[serde(default = "default_flush_ms")]
  pub log_flush_ms: u64,
}

impl Default for StoreConfig {
  fn default() -> Self {
    Self {
      postgres_url: default_postgres_url(),
      influx_url: default_influx_url(),
      influx_token: String::new(),
      influx_org: default_influx_org(),
      influx_bucket: default_influx_bucket(),
      log_batch_size: default_batch_size(),
      log_flush_ms: default_flush_ms(),
    }
  }
}

impl Config {
  pub fn validate(&self) -> nexus_common::Result<()> {
    use nexus_common::NexusError;

    if self.gateway.listen_addr.is_empty() {
      return Err(NexusError::ConfigValidation {
        field: "gateway.listen_addr".into(),
        reason: "must not be empty".into(),
      });
    }
    if self.gateway.control_addr.is_empty() {
      return Err(NexusError::ConfigValidation {
        field: "gateway.control_addr".into(),
        reason: "must not be empty".into(),
      });
    }
    if self.gateway.rest_addr.is_empty() {
      return Err(NexusError::ConfigValidation {
        field: "gateway.rest_addr".into(),
        reason: "must not be empty".into(),
      });
    }
    if self.gateway.metrics_addr.is_empty() {
      return Err(NexusError::ConfigValidation {
        field: "gateway.metrics_addr".into(),
        reason: "must not be empty".into(),
      });
    }
    if self.gateway.pid_file.is_empty() {
      return Err(NexusError::ConfigValidation {
        field: "gateway.pid_file".into(),
        reason: "must not be empty".into(),
      });
    }

    if self.lb.upstreams.is_empty() {
      return Err(NexusError::ConfigValidation {
        field: "lb.upstreams".into(),
        reason: "at least one upstream must be configured".into(),
      });
    }

    if !(0.0..=1.0).contains(&self.pipeline.risk_threshold) {
      return Err(NexusError::ConfigValidation {
        field: "pipeline.risk_threshold".into(),
        reason: "must be between 0.0 and 1.0".into(),
      });
    }

    if self.policy.timeout_ms == 0 {
      return Err(NexusError::ConfigValidation {
        field: "policy.timeout_ms".into(),
        reason: "must be greater than 0".into(),
      });
    }
    if self.policy.latency_budget_ms == 0 {
      return Err(NexusError::ConfigValidation {
        field: "policy.latency_budget_ms".into(),
        reason: "must be greater than 0".into(),
      });
    }
    if !(0.0..=1.0).contains(&self.policy.threshold_step) {
      return Err(NexusError::ConfigValidation {
        field: "policy.threshold_step".into(),
        reason: "must be between 0.0 and 1.0".into(),
      });
    }
    if !(0.0..=1.0).contains(&self.policy.attack_rate_threshold) {
      return Err(NexusError::ConfigValidation {
        field: "policy.attack_rate_threshold".into(),
        reason: "must be between 0.0 and 1.0".into(),
      });
    }
    if self.policy.rate_limit_seconds == 0 {
      return Err(NexusError::ConfigValidation {
        field: "policy.rate_limit_seconds".into(),
        reason: "must be greater than 0".into(),
      });
    }

    if self.anomaly.window_secs == 0 {
      return Err(NexusError::ConfigValidation {
        field: "anomaly.window_secs".into(),
        reason: "must be greater than 0".into(),
      });
    }
    if self.anomaly.z_score_threshold <= 0.0 {
      return Err(NexusError::ConfigValidation {
        field: "anomaly.z_score_threshold".into(),
        reason: "must be greater than 0".into(),
      });
    }
    if self.anomaly.min_samples == 0 {
      return Err(NexusError::ConfigValidation {
        field: "anomaly.min_samples".into(),
        reason: "must be greater than 0".into(),
      });
    }
    if !(0.0..=1.0).contains(&self.anomaly.ewma_alpha) {
      return Err(NexusError::ConfigValidation {
        field: "anomaly.ewma_alpha".into(),
        reason: "must be between 0.0 and 1.0".into(),
      });
    }

    if self.rate.requests_per_second == 0 {
      return Err(NexusError::ConfigValidation {
        field: "rate.requests_per_second".into(),
        reason: "must be greater than 0".into(),
      });
    }

    if self.store.log_batch_size == 0 {
      return Err(NexusError::ConfigValidation {
        field: "store.log_batch_size".into(),
        reason: "must be greater than 0".into(),
      });
    }

    if self.store.log_flush_ms == 0 {
      return Err(NexusError::ConfigValidation {
        field: "store.log_flush_ms".into(),
        reason: "must be greater than 0".into(),
      });
    }

    Ok(())
  }
}

fn default_max_body_bytes() -> usize {
  1024 * 1024
} // 1 MiB
fn default_rest_addr() -> String {
  "0.0.0.0:9091".into()
}
fn default_metrics_addr() -> String {
  "0.0.0.0:9092".into()
}
fn default_pid_file() -> String {
  let mut p: PathBuf = std::env::temp_dir();
  p.push("nexus-gateway.pid");
  p.to_string_lossy().to_string()
}
fn default_request_timeout_ms() -> u64 {
  30_000
}
fn default_risk_threshold() -> f32 {
  0.7
}
fn default_rps() -> u32 {
  1000
}
fn default_burst() -> u32 {
  200
}
fn default_window_secs() -> u64 {
  1
}
fn default_cleanup_secs() -> u64 {
  300
}
fn default_lexical_risk_delta() -> f32 {
  0.4
}
fn default_health_check_secs() -> u64 {
  10
}
fn default_unhealthy_threshold() -> u32 {
  3
}
fn default_healthy_threshold() -> u32 {
  2
}
fn default_weight() -> u32 {
  1
}
fn default_ml_endpoint() -> String {
  "http://127.0.0.1:50051".into()
}
fn default_ml_timeout_ms() -> u64 {
  10_000
}
fn default_ml_risk_delta() -> f32 {
  0.6
}
fn default_ml_threshold() -> f32 {
  0.8
}
fn default_policy_endpoint() -> String {
  "http://127.0.0.1:50053".into()
}
fn default_policy_timeout_ms() -> u64 {
  2_000
}
fn default_policy_latency_budget_ms() -> u64 {
  20
}
fn default_policy_threshold_step() -> f32 {
  0.1
}
fn default_policy_rate_limit_seconds() -> u32 {
  30
}
fn default_policy_attack_rate_threshold() -> f32 {
  0.3
}
fn default_anomaly_window_secs() -> u64 {
  10
}
fn default_anomaly_z_threshold() -> f32 {
  3.0
}
fn default_anomaly_min_samples() -> u64 {
  50
}
fn default_anomaly_risk_delta() -> f32 {
  0.2
}
fn default_anomaly_ewma_alpha() -> f32 {
  0.2
}
fn default_anomaly_cooldown_secs() -> u64 {
  30
}
fn default_postgres_url() -> String {
  "postgres://nexus:nexus@localhost:5432/nexus_waf".into()
}
fn default_influx_url() -> String {
  "http://localhost:8086".into()
}
fn default_influx_org() -> String {
  "nexus".into()
}
fn default_influx_bucket() -> String {
  "waf_metrics".into()
}
fn default_batch_size() -> usize {
  100
}
fn default_flush_ms() -> u64 {
  500
}
fn bool_true() -> bool {
  true
}
