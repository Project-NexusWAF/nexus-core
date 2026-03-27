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
  #[serde(default)]
  pub gps: GpsConfig,
  #[serde(default)]
  pub slack: SlackConfig,
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

  #[serde(default)]
  pub tls: TlsConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub cert_path: String,
  #[serde(default)]
  pub key_path: String,
  #[serde(default)]
  pub certbot: CertbotConfig,
}

impl Default for TlsConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      cert_path: String::new(),
      key_path: String::new(),
      certbot: CertbotConfig::default(),
    }
  }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertbotConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default = "default_certbot_bin")]
  pub certbot_bin: String,
  #[serde(default = "default_certbot_live_dir")]
  pub live_dir: String,
  #[serde(default)]
  pub cert_name: String,
  #[serde(default)]
  pub domain: String,
  #[serde(default)]
  pub extra_domains: Vec<String>,
  #[serde(default)]
  pub email: String,
  #[serde(default = "default_certbot_webroot_dir")]
  pub webroot_dir: String,
  #[serde(default = "default_certbot_challenge_addr")]
  pub challenge_addr: String,
  #[serde(default = "default_certbot_renew_interval_hours")]
  pub renew_interval_hours: u64,
  #[serde(default)]
  pub staging: bool,
}

impl Default for CertbotConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      certbot_bin: default_certbot_bin(),
      live_dir: default_certbot_live_dir(),
      cert_name: String::new(),
      domain: String::new(),
      extra_domains: Vec::new(),
      email: String::new(),
      webroot_dir: default_certbot_webroot_dir(),
      challenge_addr: default_certbot_challenge_addr(),
      renew_interval_hours: default_certbot_renew_interval_hours(),
      staging: false,
    }
  }
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
pub struct GpsConfig {
  #[serde(default = "bool_true")]
  pub enabled: bool,
  #[serde(default = "default_gps_lookback_hours")]
  pub default_lookback_hours: i64,
  #[serde(default = "default_gps_min_hits")]
  pub min_hits: i64,
  #[serde(default = "default_gps_max_rules")]
  pub max_rules: usize,
}

impl Default for GpsConfig {
  fn default() -> Self {
    Self {
      enabled: true,
      default_lookback_hours: default_gps_lookback_hours(),
      min_hits: default_gps_min_hits(),
      max_rules: default_gps_max_rules(),
    }
  }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SlackSeverity {
  Low,
  #[default]
  Medium,
  High,
  Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlackConfig {
  #[serde(default)]
  pub enabled: bool,
  #[serde(default)]
  pub webhook_url: String,
  #[serde(default)]
  pub channel: String,
  #[serde(default)]
  pub username: String,
  #[serde(default)]
  pub icon_emoji: String,
  #[serde(default)]
  pub min_severity: SlackSeverity,
  #[serde(default = "bool_true")]
  pub include_rate_limits: bool,
}

impl Default for SlackConfig {
  fn default() -> Self {
    Self {
      enabled: false,
      webhook_url: String::new(),
      channel: String::new(),
      username: "NexusWAF".to_string(),
      icon_emoji: ":shield:".to_string(),
      min_severity: SlackSeverity::Medium,
      include_rate_limits: true,
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
    if self.gateway.tls.enabled
      && !self.gateway.tls.certbot.enabled
      && self.gateway.tls.cert_path.trim().is_empty()
    {
      return Err(NexusError::ConfigValidation {
        field: "gateway.tls.cert_path".into(),
        reason: "must not be empty when TLS is enabled".into(),
      });
    }
    if self.gateway.tls.enabled
      && !self.gateway.tls.certbot.enabled
      && self.gateway.tls.key_path.trim().is_empty()
    {
      return Err(NexusError::ConfigValidation {
        field: "gateway.tls.key_path".into(),
        reason: "must not be empty when TLS is enabled".into(),
      });
    }
    if self.gateway.tls.certbot.enabled && !self.gateway.tls.enabled {
      return Err(NexusError::ConfigValidation {
        field: "gateway.tls.certbot.enabled".into(),
        reason: "requires gateway.tls.enabled = true".into(),
      });
    }
    if self.gateway.tls.certbot.enabled && self.gateway.tls.certbot.domain.trim().is_empty() {
      return Err(NexusError::ConfigValidation {
        field: "gateway.tls.certbot.domain".into(),
        reason: "must not be empty when Certbot automation is enabled".into(),
      });
    }
    if self.gateway.tls.certbot.enabled && self.gateway.tls.certbot.email.trim().is_empty() {
      return Err(NexusError::ConfigValidation {
        field: "gateway.tls.certbot.email".into(),
        reason: "must not be empty when Certbot automation is enabled".into(),
      });
    }
    if self.gateway.tls.certbot.enabled && self.gateway.tls.certbot.webroot_dir.trim().is_empty() {
      return Err(NexusError::ConfigValidation {
        field: "gateway.tls.certbot.webroot_dir".into(),
        reason: "must not be empty when Certbot automation is enabled".into(),
      });
    }
    if self.gateway.tls.certbot.enabled
      && self.gateway.tls.certbot.challenge_addr.trim().is_empty()
    {
      return Err(NexusError::ConfigValidation {
        field: "gateway.tls.certbot.challenge_addr".into(),
        reason: "must not be empty when Certbot automation is enabled".into(),
      });
    }
    if self.gateway.tls.certbot.enabled && self.gateway.tls.certbot.live_dir.trim().is_empty() {
      return Err(NexusError::ConfigValidation {
        field: "gateway.tls.certbot.live_dir".into(),
        reason: "must not be empty when Certbot automation is enabled".into(),
      });
    }
    if self.gateway.tls.certbot.enabled && self.gateway.tls.certbot.renew_interval_hours == 0 {
      return Err(NexusError::ConfigValidation {
        field: "gateway.tls.certbot.renew_interval_hours".into(),
        reason: "must be greater than 0 when Certbot automation is enabled".into(),
      });
    }
    if self.gateway.tls.certbot.enabled
      && self.gateway.tls.certbot.challenge_addr == self.gateway.listen_addr
    {
      return Err(NexusError::ConfigValidation {
        field: "gateway.tls.certbot.challenge_addr".into(),
        reason: "must differ from gateway.listen_addr so the ACME challenge server can bind separately".into(),
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
    if self.gps.default_lookback_hours <= 0 {
      return Err(NexusError::ConfigValidation {
        field: "gps.default_lookback_hours".into(),
        reason: "must be greater than 0".into(),
      });
    }
    if self.gps.min_hits <= 0 {
      return Err(NexusError::ConfigValidation {
        field: "gps.min_hits".into(),
        reason: "must be greater than 0".into(),
      });
    }
    if self.gps.max_rules == 0 {
      return Err(NexusError::ConfigValidation {
        field: "gps.max_rules".into(),
        reason: "must be greater than 0".into(),
      });
    }
    if self.slack.enabled && self.slack.webhook_url.trim().is_empty() {
      return Err(NexusError::ConfigValidation {
        field: "slack.webhook_url".into(),
        reason: "must not be empty when Slack alerts are enabled".into(),
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
fn default_certbot_bin() -> String {
  "certbot".into()
}
fn default_certbot_live_dir() -> String {
  if cfg!(windows) {
    "C:/Certbot/live".into()
  } else {
    "/etc/letsencrypt/live".into()
  }
}
fn default_certbot_webroot_dir() -> String {
  let mut p: PathBuf = std::env::temp_dir();
  p.push("nexus-certbot-webroot");
  p.to_string_lossy().to_string()
}
fn default_certbot_challenge_addr() -> String {
  "0.0.0.0:80".into()
}
fn default_certbot_renew_interval_hours() -> u64 {
  12
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
fn default_gps_lookback_hours() -> i64 {
  24
}
fn default_gps_min_hits() -> i64 {
  3
}
fn default_gps_max_rules() -> usize {
  8
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
