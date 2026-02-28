/// The verdict a layer or the pipeline produces for a request.
///
/// Designed as a simple enum so match arms are exhaustive and the
/// compiler enforces every callsite handles all cases.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Decision {
  Allow,
  Block { reason: String, code: BlockCode },
  Log { reason: String },
  RateLimit { retry_after_seconds: u32 },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BlockCode {
  SqlInjection,
  CrossSiteScripting,
  CommandInjection,
  PathTraversal,
  ProtocolViolation,
  MalformedPayload,
  MlDetectedThreat,
  Custom(String),
}

impl Decision {
  pub fn is_blocking(&self) -> bool {
    matches!(self, Decision::Block { .. } | Decision::RateLimit { .. })
  }
  pub fn is_allowing(&self) -> bool {
    matches!(self, Decision::Allow | Decision::Log { .. })
  }
  pub fn merge(self, other: Decision) -> Decision {
    match (&self, &other) {
      (Decision::Block { .. }, _) => self,
      (_, Decision::Block { .. }) => other,
      (Decision::RateLimit { .. }, _) => self,
      (_, Decision::RateLimit { .. }) => other,
      (Decision::Log { .. }, _) => self,
      _ => other,
    }
  }
  pub fn block(reason: impl Into<String>, code: BlockCode) -> Self {
    Decision::Block {
      reason: reason.into(),
      code,
    }
  }
  pub fn http_status(&self) -> u16 {
    match self {
      Decision::Allow | Decision::Log { .. } => 200,
      Decision::Block { .. } => 405,
      Decision::RateLimit { .. } => 429,
    }
  }
}

impl std::fmt::Display for Decision {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Decision::Allow => write!(f, "Allow"),
      Decision::Block { reason, code } => write!(f, "Block: {} ({:?})", reason, code),
      Decision::Log { reason } => write!(f, "Log: {}", reason),
      Decision::RateLimit {
        retry_after_seconds,
      } => {
        write!(f, "RateLimit: retry after {} seconds", retry_after_seconds)
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn block_is_blocking() {
    let d = Decision::block("sqli detected", BlockCode::SqlInjection);
    assert!(d.is_blocking());
    assert!(!d.is_allowing());
  }

  #[test]
  fn allow_is_not_blocking() {
    assert!(!Decision::Allow.is_blocking());
    assert!(Decision::Allow.is_allowing());
  }

  #[test]
  fn merge_takes_more_severe() {
    let allow = Decision::Allow;
    let log = Decision::Log {
      reason: "suspicious".into(),
    };
    let block = Decision::block("sqli", BlockCode::SqlInjection);

    assert_eq!(allow.merge(log.clone()), log);
    assert!(log.merge(block.clone()).is_blocking());
    // Block always wins
    let rate = Decision::RateLimit {
      retry_after_seconds: 60,
    };
    assert!(block.merge(rate).is_blocking());
  }
}
