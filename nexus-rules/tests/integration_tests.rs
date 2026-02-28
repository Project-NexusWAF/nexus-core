/// Integration tests for the nexus-rules crate
use bytes::Bytes;
use http::{HeaderMap, Method, Version};
use nexus_common::RequestContext;
use nexus_rules::{Condition, Rule, RuleAction, RuleEngine, RuleLayer, RuleSet};
use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tempfile::NamedTempFile;

fn make_ctx(uri: &str, method: Method, ip: IpAddr) -> RequestContext {
    RequestContext::new(
        ip,
        method,
        uri.parse().unwrap(),
        Version::HTTP_11,
        HeaderMap::new(),
        Bytes::new(),
    )
}

#[test]
fn test_complete_workflow() {
    // Create a comprehensive TOML configuration
    let toml_content = r#"
version = "2.5.0"

# Whitelist health checks
[[rules]]
id = "R001"
name = "Allow health checks"
enabled = true
priority = 5
action = "allow"
description = "Whitelist monitoring endpoints"

[rules.condition]
type = "or"
conditions = [
    { type = "path_exact", value = "/health" },
    { type = "path_exact", value = "/status" }
]

# Block admin access from external IPs
[[rules]]
id = "R002"
name = "Block external admin access"
enabled = true
priority = 10
action = "block"
description = "Prevent admin access from non-private IPs"

[rules.condition]
type = "and"
conditions = [
    { type = "path_prefix", value = "/admin" },
    { type = "not", condition = { type = "ip_in_range", cidrs = ["10.0.0.0/8", "192.168.0.0/16", "172.16.0.0/12"] } }
]

# Log high-risk requests
[[rules]]
id = "R003"
name = "Log high-risk"
enabled = true
priority = 20
action = "log"
description = "Record high-risk activity"

[rules.condition]
type = "risk_above"
threshold = 0.7

# Block specific attack patterns
[[rules]]
id = "R004"
name = "Block SQL injection patterns"
enabled = true
priority = 30
action = "block"
description = "Detect SQL injection in URI"

[rules.condition]
type = "regex_match"
target = "uri"
pattern = "(?i)(union.*select|drop.*table|;.*--)"

# Disabled rule (should not fire)
[[rules]]
id = "R999"
name = "Disabled test rule"
enabled = false
priority = 1
action = "block"

[rules.condition]
type = "path_prefix"
value = "/"
"#;

    let mut temp_file = NamedTempFile::new().unwrap();
    temp_file.write_all(toml_content.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    // Load ruleset
    let ruleset = RuleSet::from_file(temp_file.path()).unwrap();
    assert_eq!(ruleset.version, "2.5.0");
    assert_eq!(ruleset.rules.len(), 5);

    let engine = RuleEngine::new(ruleset);
    assert_eq!(engine.version(), "2.5.0");
    assert_eq!(engine.active_rule_count(), 4); // One is disabled

    // Test 1: Health check should be whitelisted
    let mut ctx = make_ctx(
        "http://example.com/health",
        Method::GET,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
    );
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_allowed());

    // Test 2: Admin from external IP should be blocked
    let mut ctx = make_ctx(
        "http://example.com/admin/users",
        Method::GET,
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
    );
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_blocked());
    assert!(ctx.threat_tags.contains(&"R002".to_string()));

    // Test 3: Admin from internal IP should pass R002
    let mut ctx = make_ctx(
        "http://example.com/admin/users",
        Method::GET,
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)),
    );
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_allowed());
    assert!(!ctx.threat_tags.contains(&"R002".to_string()));

    // Test 4: High risk request should be logged but allowed
    let mut ctx = make_ctx(
        "http://example.com/api/data",
        Method::POST,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    );
    ctx.risk_score = 0.85;
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_allowed());
    assert!(ctx.threat_tags.contains(&"R003".to_string()));

    // Test 5: SQL injection pattern should be blocked
    let mut ctx = make_ctx(
        "http://example.com/search?q=1' UNION SELECT * FROM users--",
        Method::GET,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    );
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_blocked());
    assert!(ctx.threat_tags.contains(&"R004".to_string()));

    // Test 6: Normal request should pass all rules
    let mut ctx = make_ctx(
        "http://example.com/api/products",
        Method::GET,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    );
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_allowed());
    assert!(ctx.threat_tags.is_empty());
}

#[test]
fn test_ipv6_cidr_ranges() {
    let ruleset = RuleSet {
        version: "1.0.0".to_string(),
        rules: vec![Rule {
            id: "R_IPV6".to_string(),
            name: "Block IPv6 range".to_string(),
            enabled: true,
            priority: 10,
            action: RuleAction::Block,
            description: String::new(),
            condition: Condition::IpInRange {
                cidrs: vec!["2001:db8::/32".to_string()],
            },
        }],
    };

    let engine = RuleEngine::new(ruleset);

    // Should block
    let mut ctx = make_ctx(
        "http://example.com/",
        Method::GET,
        IpAddr::V6("2001:db8::1".parse().unwrap()),
    );
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_blocked());

    // Should allow
    let mut ctx = make_ctx(
        "http://example.com/",
        Method::GET,
        IpAddr::V6("2001:db9::1".parse().unwrap()),
    );
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_allowed());
}

#[test]
fn test_complex_nested_conditions() {
    // (MethodIs AND PathPrefix) OR (HasTag AND RiskAbove)
    let ruleset = RuleSet {
        version: "1.0.0".to_string(),
        rules: vec![Rule {
            id: "R_COMPLEX".to_string(),
            name: "Complex condition".to_string(),
            enabled: true,
            priority: 10,
            action: RuleAction::Block,
            description: String::new(),
            condition: Condition::Or {
                conditions: vec![
                    Condition::And {
                        conditions: vec![
                            Condition::MethodIs {
                                methods: vec!["DELETE".to_string()],
                            },
                            Condition::PathPrefix {
                                value: "/api".to_string(),
                            },
                        ],
                    },
                    Condition::And {
                        conditions: vec![
                            Condition::HasTag {
                                tag: "suspicious".to_string(),
                            },
                            Condition::RiskAbove { threshold: 0.5 },
                        ],
                    },
                ],
            },
        }],
    };

    let engine = RuleEngine::new(ruleset);

    // Match first branch: DELETE + /api
    let mut ctx = make_ctx(
        "http://example.com/api/users",
        Method::DELETE,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    );
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_blocked());

    // Match second branch: has tag + high risk
    let mut ctx = make_ctx(
        "http://example.com/other",
        Method::GET,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    );
    ctx.threat_tags.push("suspicious".to_string());
    ctx.risk_score = 0.8;
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_blocked());

    // No match: GET on /api (wrong method)
    let mut ctx = make_ctx(
        "http://example.com/api/data",
        Method::GET,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    );
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_allowed());

    // No match: has tag but risk too low
    let mut ctx = make_ctx(
        "http://example.com/",
        Method::GET,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    );
    ctx.threat_tags.push("suspicious".to_string());
    ctx.risk_score = 0.3;
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_allowed());
}

#[test]
fn test_header_matching() {
    let ruleset = RuleSet {
        version: "1.0.0".to_string(),
        rules: vec![Rule {
            id: "R_HDR".to_string(),
            name: "Block bot user agents".to_string(),
            enabled: true,
            priority: 10,
            action: RuleAction::Block,
            description: String::new(),
            condition: Condition::HeaderContains {
                header: "user-agent".to_string(),
                value: "bot".to_string(),
            },
        }],
    };

    let engine = RuleEngine::new(ruleset);

    let mut headers = HeaderMap::new();
    headers.insert("user-agent", "BadBot/1.0".parse().unwrap());

    let mut ctx = RequestContext::new(
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
        Method::GET,
        "http://example.com/".parse().unwrap(),
        Version::HTTP_11,
        headers,
        Bytes::new(),
    );

    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_blocked());
}

#[tokio::test]
async fn test_rule_layer_integration() {
    use nexus_common::Layer;

    let ruleset = RuleSet {
        version: "1.0.0".to_string(),
        rules: vec![Rule {
            id: "R_LAYER".to_string(),
            name: "Test layer rule".to_string(),
            enabled: true,
            priority: 10,
            action: RuleAction::Block,
            description: String::new(),
            condition: Condition::PathPrefix {
                value: "/blocked".to_string(),
            },
        }],
    };

    let engine = RuleEngine::new(ruleset);
    let layer = RuleLayer::new(engine);

    assert_eq!(layer.name(), "rules");
    assert_eq!(layer.priority(), 30);

    let mut ctx = make_ctx(
        "http://example.com/blocked/resource",
        Method::GET,
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    );

    let decision = layer.analyse(&mut ctx).await.unwrap();
    assert!(decision.is_blocked());
    assert_eq!(ctx.flagged_by, Some("rules".to_string()));
}

#[test]
fn test_reload_error_handling() {
    let valid_toml = r#"
version = "1.0.0"
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
    temp_file.write_all(valid_toml.as_bytes()).unwrap();
    temp_file.flush().unwrap();

    let ruleset = RuleSet::from_file(temp_file.path()).unwrap();
    let engine = RuleEngine::new(ruleset);

    // Try to reload from non-existent file
    let result = engine.reload_from_file("/nonexistent/file.toml");
    assert!(result.is_err());

    // Original ruleset should still be intact
    assert_eq!(engine.version(), "1.0.0");
    assert_eq!(engine.active_rule_count(), 1);
}

#[test]
fn test_regex_performance() {
    // Test that regex caching works by calling same pattern multiple times
    let ruleset = RuleSet {
        version: "1.0.0".to_string(),
        rules: vec![Rule {
            id: "R_REGEX".to_string(),
            name: "Regex test".to_string(),
            enabled: true,
            priority: 10,
            action: RuleAction::Block,
            description: String::new(),
            condition: Condition::RegexMatch {
                target: "uri".to_string(),
                pattern: r"\d{3}-\d{3}-\d{4}".to_string(),
            },
        }],
    };

    let engine = RuleEngine::new(ruleset);

    // First call - compiles regex
    let mut ctx = make_ctx(
        "http://example.com/phone/123-456-7890",
        Method::GET,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    );
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_blocked());

    // Second call - should use cached regex
    let mut ctx = make_ctx(
        "http://example.com/phone/987-654-3210",
        Method::GET,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    );
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_blocked());

    // Non-matching pattern
    let mut ctx = make_ctx(
        "http://example.com/phone/invalid",
        Method::GET,
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
    );
    let decision = engine.evaluate(&mut ctx).unwrap();
    assert!(decision.is_allowed());
}
