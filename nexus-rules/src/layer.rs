use crate::engine::RuleEngine;
use async_trait::async_trait;
use nexus_common::{Decision, InnerLayer, RequestContext};
use std::sync::Arc;

/// Layer implementation for the rule engine
pub struct RuleLayer {
    engine: Arc<RuleEngine>,
}

impl RuleLayer {
    /// Create a new rule layer with the given engine
    pub fn new(engine: Arc<RuleEngine>) -> Self {
        Self { engine }
    }
}

#[async_trait]
impl InnerLayer for RuleLayer {
    fn name(&self) -> &'static str {
        "rules"
    }

    fn priority(&self) -> u8 {
        30
    }

    async fn analyse(&self, ctx: &mut RequestContext) -> nexus_common::Result<Decision> {
        self.engine.evaluate(ctx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::condition::Condition;
    use crate::rule::{Rule, RuleAction, RuleSet};
    use bytes::Bytes;
    use http::{HeaderMap, Method, Version};
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn layer_evaluates_rules() {
        let ruleset = RuleSet {
            version: "1.0.0".to_string(),
            rules: vec![Rule {
                id: "R001".to_string(),
                name: "Test rule".to_string(),
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

        let mut ctx = RequestContext::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            Method::GET,
            "http://example.com/blocked/path".parse().unwrap(),
            Version::HTTP_11,
            HeaderMap::new(),
            Bytes::new(),
        );

        let decision = layer.analyse(&mut ctx).await.unwrap();
        assert!(decision.is_blocked());
    }

    #[test]
    fn layer_has_correct_priority() {
        let ruleset = RuleSet {
            version: "1.0.0".to_string(),
            rules: vec![],
        };

        let engine = RuleEngine::new(ruleset);
        let layer = RuleLayer::new(engine);

        assert_eq!(layer.name(), "rules");
        assert_eq!(layer.priority(), 30);
    }
}
