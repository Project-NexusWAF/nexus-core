use async_trait::async_trait;
use tracing::warn;

use nexus_common::{Decision, InnerLayer, RequestContext, Result};
use nexus_config::LexicalConfig;

use crate::ast::AstFinding;
use crate::scanner::GrammarScanner;

pub struct GrammarLayer {
  scanner: GrammarScanner,
  block_on_match: bool,
  sqli_enabled: bool,
  xss_enabled: bool,
}

impl GrammarLayer {
  pub fn new(block_on_match: bool) -> Self {
    Self {
      scanner: GrammarScanner::new(),
      block_on_match,
      sqli_enabled: true,
      xss_enabled: true,
    }
  }

  pub fn from_config(cfg: &LexicalConfig) -> Self {
    Self {
      scanner: GrammarScanner::new(),
      block_on_match: cfg.block_on_match,
      sqli_enabled: cfg.sqli_enabled,
      xss_enabled: cfg.xss_enabled,
    }
  }

  fn finding_enabled(&self, finding: &AstFinding) -> bool {
    match finding.as_tag() {
      "sqli" => self.sqli_enabled,
      "xss" => self.xss_enabled,
      _ => true,
    }
  }
}

#[async_trait]
impl InnerLayer for GrammarLayer {
  fn name(&self) -> &'static str {
    "grammar"
  }

  fn priority(&self) -> u8 {
    20
  }

  async fn analyse(&self, ctx: &mut RequestContext) -> Result<Decision> {
    let uri = ctx.uri.clone();
    let body = String::from_utf8_lossy(&ctx.body).to_string();
    let user_agent = ctx
      .headers
      .0
      .get("user-agent")
      .and_then(|v| v.to_str().ok())
      .unwrap_or("")
      .to_string();

    let mut inputs = vec![(uri.as_str(), "uri")];
    if !body.is_empty() {
      inputs.push((body.as_str(), "body"));
    }
    if !user_agent.is_empty() {
      inputs.push((user_agent.as_str(), "user-agent"));
    }

    let mut findings = self.scanner.scan(&inputs);
    findings.retain(|f| self.finding_enabled(&f.finding));

    if findings.is_empty() {
      return Ok(Decision::Allow);
    }

    let mut grammar_risk = 0.0f32;
    for finding in &findings {
      warn!(
        request_id = %ctx.id,
        source = finding.source,
        category = finding.finding.as_tag(),
        issue = finding.finding.description(),
        "Grammar threat detected"
      );
      ctx.tag(finding.finding.as_tag(), self.name());
      let delta = finding.finding.risk_delta();
      ctx.add_risk(delta);
      grammar_risk += delta;
    }

    if grammar_risk > 0.0 {
      ctx
        .meta
        .insert("grammar_risk".into(), format!("{:.3}", grammar_risk));
    }

    if self.block_on_match {
      if let Some(worst) = findings.iter().max_by_key(|f| f.finding.severity_rank()) {
        return Ok(Decision::block(
          format!("Grammar threat detected: {}", worst.finding.description()),
          worst.finding.block_code(),
        ));
      }
    }

    Ok(Decision::Allow)
  }
}

#[cfg(test)]
mod tests {
  use super::GrammarLayer;
  use bytes::Bytes;
  use futures::executor::block_on;
  use http::{HeaderMap, HeaderValue, Method, Version};
  use nexus_common::{BlockCode, Decision, InnerLayer, RequestContext};
  use nexus_config::LexicalConfig;
  use std::net::{IpAddr, Ipv4Addr};

  fn make_ctx(uri: &str, body: &[u8], user_agent: Option<&str>) -> RequestContext {
    let mut headers = HeaderMap::new();
    if let Some(ua) = user_agent {
      headers.insert("user-agent", HeaderValue::from_str(ua).unwrap());
    }

    RequestContext::new(
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
      Method::GET,
      uri.parse().unwrap(),
      Version::HTTP_11,
      headers,
      Bytes::copy_from_slice(body),
    )
  }

  #[test]
  fn name_and_priority_are_fixed() {
    let layer = GrammarLayer::new(false);
    assert_eq!(layer.name(), "grammar");
    assert_eq!(layer.priority(), 20);
  }

  #[test]
  fn clean_request_returns_allow() {
    let layer = GrammarLayer::new(false);
    let mut ctx = make_ctx(
      "http://example.com/search?q=rust",
      b"safe body",
      Some("Mozilla/5.0"),
    );
    let decision = block_on(layer.analyse(&mut ctx)).unwrap();
    assert_eq!(decision, Decision::Allow);
  }

  #[test]
  fn non_blocking_mode_tags_and_accumulates_risk() {
    let layer = GrammarLayer::new(false);
    let mut ctx = make_ctx(
      "http://example.com/search",
      b"1 UNION SELECT username",
      None,
    );

    let decision = block_on(layer.analyse(&mut ctx)).unwrap();
    assert_eq!(decision, Decision::Allow);
    assert!(ctx.threat_tags.contains("sqli"));
    assert!(ctx.risk_score > 0.0);
  }

  #[test]
  fn block_mode_returns_block_with_expected_code() {
    let layer = GrammarLayer::new(true);
    let mut ctx = make_ctx("http://example.com/", b"<script>alert(1)</script>", None);

    let decision = block_on(layer.analyse(&mut ctx)).unwrap();
    match decision {
      Decision::Block { reason, code } => {
        assert_eq!(code, BlockCode::CrossSiteScripting);
        assert!(!reason.contains("<script>"));
      }
      other => panic!("expected block decision, got {other:?}"),
    }
  }

  #[test]
  fn config_toggles_disable_detector_family() {
    let cfg = LexicalConfig {
      sqli_enabled: false,
      xss_enabled: true,
      path_traversal_enabled: true,
      cmd_injection_enabled: true,
      risk_delta: 0.4,
      block_on_match: false,
    };
    let layer = GrammarLayer::from_config(&cfg);
    let mut ctx = make_ctx(
      "http://example.com/search?q=1%20UNION%20SELECT%20username",
      b"",
      None,
    );

    let decision = block_on(layer.analyse(&mut ctx)).unwrap();
    assert_eq!(decision, Decision::Allow);
    assert!(!ctx.threat_tags.contains("sqli"));
    assert_eq!(ctx.risk_score, 0.0);
  }

  #[test]
  fn malformed_percent_payload_does_not_error() {
    let layer = GrammarLayer::new(false);
    let mut ctx = make_ctx("http://example.com/?q=%zz%2%", b"", None);
    let decision = block_on(layer.analyse(&mut ctx));
    assert!(decision.is_ok());
  }

  #[test]
  fn non_utf8_body_is_handled_lossy_without_error() {
    let layer = GrammarLayer::new(false);
    let body = [0xff, 0xfe, b'<', b's', b'c', b'r', b'i', b'p', b't', b'>'];
    let mut ctx = make_ctx("http://example.com/", &body, None);
    let decision = block_on(layer.analyse(&mut ctx));
    assert!(decision.is_ok());
  }
}
