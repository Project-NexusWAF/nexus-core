/// Root configuration for the entire nexus-core data plane.
/// Loaded from TOML, with environment variable overrides.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
  pub gateway: GatewayConfig,
  pub pipeline: PipelineConfig,
  pub rate: RateConfig,
  pub lexical: LexicalConfig,
  pub lb: LbConfig,

  #[serde(default)]
  pub ml: MlConfig,
  pub rules: RulesConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
  pub listen_addr: String,
  pub control_addr: String,
  pub metrics_addr: String,

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RulesConfig {
  pub rules_file: String,

  #[serde(default = "bool_true")]
  pub fail_closed: bool,
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

    if self.rate.requests_per_second == 0 {
      return Err(NexusError::ConfigValidation {
        field: "rate.requests_per_second".into(),
        reason: "must be greater than 0".into(),
      });
    }

    Ok(())
  }
}

fn default_max_body_bytes() -> usize {
  1024 * 1024
} // 1 MiB
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
fn bool_true() -> bool {
  true
}
