use crate::rule::{RuleAction, RuleSet};
use nexus_common::{BlockCode, Decision, RequestContext};
use parking_lot::RwLock;
use std::path::Path;
use std::sync::Arc;

/// The rule evaluation engine
pub struct RuleEngine {
  ruleset: RwLock<RuleSet>,
}

impl RuleEngine {
  /// Create a new rule engine with the given ruleset
  pub fn new(ruleset: RuleSet) -> Arc<Self> {
    Arc::new(Self {
      ruleset: RwLock::new(ruleset),
    })
  }

  /// Evaluate all active rules against a request context
  pub fn evaluate(&self, ctx: &mut RequestContext) -> nexus_common::Result<Decision> {
    let ruleset = self.ruleset.read();
    let active_rules = ruleset.active_rules();

    for rule in active_rules {
      if rule.condition.matches(ctx) {
        match &rule.action {
          RuleAction::Block => {
            ctx.tag(&rule.id, "rules");
            tracing::warn!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                request_id = %ctx.id,
                client_ip = %ctx.client_ip,
                uri = %ctx.uri,
                "Rule matched - blocking request"
            );
            return Ok(Decision::block(
              format!("Rule {} matched: {}", rule.id, rule.name),
              BlockCode::ProtocolViolation,
            ));
          }
          RuleAction::Allow => {
            tracing::info!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                request_id = %ctx.id,
                client_ip = %ctx.client_ip,
                uri = %ctx.uri,
                "Rule matched - allowing request (whitelist)"
            );
            return Ok(Decision::Allow);
          }
          RuleAction::Log => {
            ctx.tag(&rule.id, "rules");
            tracing::info!(
                rule_id = %rule.id,
                rule_name = %rule.name,
                request_id = %ctx.id,
                client_ip = %ctx.client_ip,
                uri = %ctx.uri,
                "Rule matched - logging and continuing"
            );
            // Continue to next rule
          }
        }
      }
    }

    // No blocking or allow rule matched
    Ok(Decision::Allow)
  }

  /// Hot-reload rules from a file
  pub fn reload_from_file(&self, path: impl AsRef<Path>) -> nexus_common::Result<()> {
    let new_ruleset = RuleSet::from_file(path)?;
    let mut ruleset = self.ruleset.write();
    *ruleset = new_ruleset;
    tracing::info!(
        version = %ruleset.version,
        rule_count = ruleset.rules.len(),
        "Rules reloaded successfully"
    );
    Ok(())
  }

  /// Get the count of currently active rules
  pub fn active_rule_count(&self) -> usize {
    let ruleset = self.ruleset.read();
    ruleset.active_rules().count()
  }

  /// Get the current ruleset version
  pub fn version(&self) -> String {
    let ruleset = self.ruleset.read();
    ruleset.version.clone()
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::condition::Condition;
  use crate::rule::Rule;
  use bytes::Bytes;
  use http::{HeaderMap, Method, Version};
  use std::io::{Seek, Write};
  use std::net::{IpAddr, Ipv4Addr};
  use tempfile::NamedTempFile;

  fn make_ctx(uri: &str, method: Method) -> RequestContext {
    RequestContext::new(
      IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
      method,
      uri.parse().unwrap(),
      Version::HTTP_11,
      HeaderMap::new(),
      Bytes::new(),
    )
  }

  fn make_ruleset(mut rules: Vec<Rule>) -> RuleSet {
    rules.sort_by_key(|r| r.priority);
    RuleSet {
      rules,
      version: "test".to_string(),
    }
  }

  #[test]
  fn block_rule_fires() {
    let ruleset = make_ruleset(vec![Rule {
      id: "R001".to_string(),
      name: "Block admin".to_string(),
      enabled: true,
      priority: 10,
      action: RuleAction::Block,
      description: String::new(),
      condition: Condition::PathPrefix {
        value: "/admin".to_string(),
      },
    }]);

    let engine = RuleEngine::new(ruleset);
    let mut ctx = make_ctx("http://example.com/admin/users", Method::GET);

    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_blocked());
    assert!(ctx.threat_tags.contains("R001"));
    assert_eq!(ctx.flagged_by, Some("rules".to_string()));
  }

  #[test]
  fn allow_rule_whitelists() {
    let ruleset = make_ruleset(vec![
      Rule {
        id: "R001".to_string(),
        name: "Whitelist health check".to_string(),
        enabled: true,
        priority: 5,
        action: RuleAction::Allow,
        description: String::new(),
        condition: Condition::PathExact {
          value: "/health".to_string(),
        },
      },
      Rule {
        id: "R002".to_string(),
        name: "Block everything else".to_string(),
        enabled: true,
        priority: 10,
        action: RuleAction::Block,
        description: String::new(),
        condition: Condition::PathPrefix {
          value: "/".to_string(),
        },
      },
    ]);

    let engine = RuleEngine::new(ruleset);
    let mut ctx = make_ctx("http://example.com/health", Method::GET);

    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_allowed());
    // Should not reach second rule
    assert!(!ctx.threat_tags.contains("R002"));
  }

  #[test]
  fn log_rule_continues() {
    let ruleset = make_ruleset(vec![
      Rule {
        id: "R001".to_string(),
        name: "Log suspicious".to_string(),
        enabled: true,
        priority: 10,
        action: RuleAction::Log,
        description: String::new(),
        condition: Condition::PathPrefix {
          value: "/api".to_string(),
        },
      },
      Rule {
        id: "R002".to_string(),
        name: "Block admin".to_string(),
        enabled: true,
        priority: 20,
        action: RuleAction::Block,
        description: String::new(),
        condition: Condition::PathPrefix {
          value: "/api/admin".to_string(),
        },
      },
    ]);

    let engine = RuleEngine::new(ruleset);
    let mut ctx = make_ctx("http://example.com/api/admin/delete", Method::POST);

    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_blocked());
    // Both rules should have tagged
    assert!(ctx.threat_tags.contains("R001"));
    assert!(ctx.threat_tags.contains("R002"));
  }

  #[test]
  fn disabled_rule_skipped() {
    let ruleset = make_ruleset(vec![Rule {
      id: "R001".to_string(),
      name: "Disabled rule".to_string(),
      enabled: false,
      priority: 10,
      action: RuleAction::Block,
      description: String::new(),
      condition: Condition::PathPrefix {
        value: "/".to_string(),
      },
    }]);

    let engine = RuleEngine::new(ruleset);
    let mut ctx = make_ctx("http://example.com/anything", Method::GET);

    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_allowed());
    assert!(ctx.threat_tags.is_empty());
  }

  #[test]
  fn priority_ordering_respected() {
    let ruleset = make_ruleset(vec![
      Rule {
        id: "R_HIGH".to_string(),
        name: "High priority block".to_string(),
        enabled: true,
        priority: 50,
        action: RuleAction::Block,
        description: String::new(),
        condition: Condition::PathPrefix {
          value: "/".to_string(),
        },
      },
      Rule {
        id: "R_LOW".to_string(),
        name: "Low priority allow".to_string(),
        enabled: true,
        priority: 10,
        action: RuleAction::Allow,
        description: String::new(),
        condition: Condition::PathPrefix {
          value: "/".to_string(),
        },
      },
    ]);

    let engine = RuleEngine::new(ruleset);
    let mut ctx = make_ctx("http://example.com/test", Method::GET);

    let decision = engine.evaluate(&mut ctx).unwrap();
    // Lower priority (10) should fire first and whitelist
    assert!(decision.is_allowed());
  }

  #[test]
  fn no_match_allows() {
    let ruleset = make_ruleset(vec![Rule {
      id: "R001".to_string(),
      name: "Block admin only".to_string(),
      enabled: true,
      priority: 10,
      action: RuleAction::Block,
      description: String::new(),
      condition: Condition::PathPrefix {
        value: "/admin".to_string(),
      },
    }]);

    let engine = RuleEngine::new(ruleset);
    let mut ctx = make_ctx("http://example.com/public", Method::GET);

    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_allowed());
    assert!(ctx.threat_tags.is_empty());
  }

  #[test]
  fn hot_reload_updates_rules() {
    let initial_toml = r#"
version = "1.0.0"

[[rules]]
id = "R001"
name = "Initial rule"
enabled = true
priority = 10
action = "block"

[rules.condition]
type = "path_prefix"
value = "/old"
"#;

    let updated_toml = r#"
version = "2.0.0"

[[rules]]
id = "R002"
name = "Updated rule"
enabled = true
priority = 10
action = "block"

[rules.condition]
type = "path_prefix"
value = "/new"
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(initial_toml.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let ruleset = RuleSet::from_file(temp_file.path()).unwrap();
    let engine = RuleEngine::new(ruleset);

    assert_eq!(engine.version(), "1.0.0");
    assert_eq!(engine.active_rule_count(), 1);

    // Update file
    temp_file.seek(std::io::SeekFrom::Start(0)).unwrap();
    temp_file.as_file_mut().set_len(0).unwrap();
    temp_file.write_all(updated_toml.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    // Hot reload
    engine.reload_from_file(temp_file.path()).unwrap();

    assert_eq!(engine.version(), "2.0.0");
    assert_eq!(engine.active_rule_count(), 1);

    // Old rule should no longer fire
    let mut ctx = make_ctx("http://example.com/old", Method::GET);
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_allowed());

    // New rule should fire
    let mut ctx = make_ctx("http://example.com/new", Method::GET);
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_blocked());
  }

  #[test]
  fn active_rule_count_excludes_disabled() {
    let ruleset = make_ruleset(vec![
      Rule {
        id: "R001".to_string(),
        name: "Enabled".to_string(),
        enabled: true,
        priority: 10,
        action: RuleAction::Block,
        description: String::new(),
        condition: Condition::PathPrefix {
          value: "/test".to_string(),
        },
      },
      Rule {
        id: "R002".to_string(),
        name: "Disabled".to_string(),
        enabled: false,
        priority: 20,
        action: RuleAction::Block,
        description: String::new(),
        condition: Condition::PathPrefix {
          value: "/test".to_string(),
        },
      },
    ]);

    let engine = RuleEngine::new(ruleset);
    assert_eq!(engine.active_rule_count(), 1);
  }
}
