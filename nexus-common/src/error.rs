/// The unified error type for all NexusWAF crates.
///
/// Each crate can define its own error variants and convert them into
/// `NexusError` via `From` implementations — keeping error propagation
/// with `?` clean throughout the codebase.
use thiserror::Error;

#[derive(Debug, Error)]
pub enum NexusError {
  #[error("Configuration error: {0}")]
  Config(String),

  #[error("Invalid configuration field '{field}': {reason}")]
  ConfigValidation { field: String, reason: String },

  #[error("Gateway error: {0}")]
  Gateway(String),

  #[error("Upstream connection failed to '{host}': {source}")]
  UpstreamConnect {
    host: String,
    #[source]
    source: Box<dyn std::error::Error + Send + Sync>,
  },

  #[error("Upstream timeout after {timeout_ms}ms")]
  UpstreamTimeout { timeout_ms: u64 },

  #[error("Pipeline layer '{layer}' failed: {reason}")]
  PipelineLayer { layer: String, reason: String },

  #[error("Rate limiter internal error: {0}")]
  RateLimiter(String),

  #[error("Lexical analysis error: {0}")]
  Lexical(String),

  #[error("Grammar parse error at position {pos}: {message}")]
  GrammarParse { pos: usize, message: String },

  #[error("ML inference unavailable: {0}")]
  MlUnavailable(String),

  #[error("ML inference timeout after {timeout_ms}ms")]
  MlTimeout { timeout_ms: u64 },

  #[error("ML response parse error: {0}")]
  MlResponseParse(String),

  #[error("Control plane error: {0}")]
  ControlPlane(String),

  #[error("No healthy upstream available")]
  NoHealthyUpstream,

  #[error("Load balancer error: {0}")]
  LoadBalancer(String),

  #[error("I/O error: {0}")]
  Io(#[from] std::io::Error),

  #[error("Serialization error: {0}")]
  Serialization(String),

  #[error("Internal error: {0}")]
  Internal(String),
}

pub type Result<T> = std::result::Result<T, NexusError>;

impl From<serde_json::Error> for NexusError {
  fn from(e: serde_json::Error) -> Self {
    NexusError::Serialization(e.to_string())
  }
}

impl From<toml::de::Error> for NexusError {
  fn from(e: toml::de::Error) -> Self {
    NexusError::Config(e.to_string())
  }
}

impl NexusError {
  pub fn http_status(&self) -> u16 {
    match self {
      NexusError::UpstreamTimeout { .. } | NexusError::MlTimeout { .. } => 504,
      NexusError::UpstreamConnect { .. } | NexusError::NoHealthyUpstream => 502,
      NexusError::Config(_) | NexusError::ConfigValidation { .. } | NexusError::Internal(_) => 500,
      _ => 500,
    }
  }

  pub fn is_retriable(&self) -> bool {
    matches!(
      self,
      NexusError::UpstreamTimeout { .. }
        | NexusError::MlTimeout { .. }
        | NexusError::NoHealthyUpstream
    )
  }
}
