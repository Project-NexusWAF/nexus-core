use crate::condition::Condition;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

/// A single security rule
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Rule {
    /// Unique identifier (e.g., "R001")
    pub id: String,
    /// Human-readable name
    pub name: String,
    /// Whether this rule is active
    pub enabled: bool,
    /// Evaluation priority (lower = first)
    pub priority: u8,
    /// Action to take on match
    pub action: RuleAction,
    /// Optional description
    #[serde(default)]
    pub description: String,
    /// Condition to evaluate
    pub condition: Condition,
}

/// Action to take when a rule matches
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleAction {
    /// Block the request (return 403)
    Block,
    /// Allow the request immediately (whitelist)
    Allow,
    /// Log a warning but continue processing
    Log,
}

/// Complete set of loaded rules
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RuleSet {
    /// List of all rules
    pub rules: Vec<Rule>,
    /// Version identifier for change tracking
    #[serde(default = "default_version")]
    pub version: String,
}

fn default_version() -> String {
    "1.0.0".to_string()
}

impl RuleSet {
    /// Load rules from a TOML file
    pub fn from_file(path: impl AsRef<Path>) -> nexus_common::Result<Self> {
        let path = path.as_ref();
        let contents = fs::read_to_string(path).map_err(|e| {
            nexus_common::NexusError::Config(format!("Failed to read rules file {:?}: {}", path, e))
        })?;

        toml::from_str(&contents).map_err(|e| {
            nexus_common::NexusError::Config(format!("Failed to parse rules TOML: {}", e))
        })
    }

    /// Get only enabled rules, sorted by priority (ascending)
    pub fn active_rules(&self) -> Vec<&Rule> {
        let mut rules: Vec<&Rule> = self.rules.iter().filter(|r| r.enabled).collect();
        rules.sort_by_key(|r| r.priority);
        rules
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::condition::Condition;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn parses_rule_from_toml() {
        let toml_content = r#"
version = "1.0.0"

[[rules]]
id = "R001"
name = "Block admin from internet"
enabled = true
priority = 10
action = "block"
description = "Prevent external access to admin panel"

[rules.condition]
type = "path_prefix"
value = "/admin"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(toml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let ruleset = RuleSet::from_file(temp_file.path()).unwrap();
        assert_eq!(ruleset.version, "1.0.0");
        assert_eq!(ruleset.rules.len(), 1);

        let rule = &ruleset.rules[0];
        assert_eq!(rule.id, "R001");
        assert_eq!(rule.name, "Block admin from internet");
        assert!(rule.enabled);
        assert_eq!(rule.priority, 10);
        assert_eq!(rule.action, RuleAction::Block);
    }

    #[test]
    fn active_rules_filters_and_sorts() {
        let ruleset = RuleSet {
            version: "1.0.0".to_string(),
            rules: vec![
                Rule {
                    id: "R3".to_string(),
                    name: "Third".to_string(),
                    enabled: true,
                    priority: 30,
                    action: RuleAction::Block,
                    description: String::new(),
                    condition: Condition::PathExact {
                        value: "/test".to_string(),
                    },
                },
                Rule {
                    id: "R1".to_string(),
                    name: "First".to_string(),
                    enabled: true,
                    priority: 10,
                    action: RuleAction::Allow,
                    description: String::new(),
                    condition: Condition::PathExact {
                        value: "/health".to_string(),
                    },
                },
                Rule {
                    id: "R2".to_string(),
                    name: "Disabled".to_string(),
                    enabled: false,
                    priority: 5,
                    action: RuleAction::Block,
                    description: String::new(),
                    condition: Condition::PathExact {
                        value: "/disabled".to_string(),
                    },
                },
            ],
        };

        let active = ruleset.active_rules();
        assert_eq!(active.len(), 2);
        assert_eq!(active[0].id, "R1"); // priority 10
        assert_eq!(active[1].id, "R3"); // priority 30
    }

    #[test]
    fn default_version_is_applied() {
        let toml_content = r#"
[[rules]]
id = "R001"
name = "Test"
enabled = true
priority = 10
action = "log"

[rules.condition]
type = "path_exact"
value = "/test"
"#;

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(toml_content.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let ruleset = RuleSet::from_file(temp_file.path()).unwrap();
        assert_eq!(ruleset.version, "1.0.0");
    }
}
