use async_trait::async_trait;
use tracing::{debug, warn};

use nexus_common::{Decision, InnerLayer, RequestContext, Result};
use nexus_config::LexicalConfig;

use crate::scanner::{LexicalScanner, MatchedIn, ThreatCategory};

/// The lexical detection layer — implements `Layer` for the pipeline.
///
/// Priority: 10 — runs after rate limiting (0) but before grammar (20) and rules (30).
///
/// Responsibilities:
/// 1. Assemble all inspectable text from the `RequestContext`.
/// 2. Run `LexicalScanner::scan()` against all text.
/// 3. Tag the context with threat categories found.
/// 4. Add risk score delta per match.
/// 5. Either block immediately (if `block_on_match`) or return `Allow`
///    and let the risk score accumulate for downstream layers.
pub struct LexicalLayer {
  scanner: LexicalScanner,
  config: LexicalConfig,
}

impl LexicalLayer {
  pub fn new(config: LexicalConfig) -> Self {
    Self {
      scanner: LexicalScanner::new(config.clone()),
      config,
    }
  }

  pub fn from_config(cfg: &nexus_config::LexicalConfig) -> Self {
    Self::new(cfg.clone())
  }
}

#[async_trait]
impl InnerLayer for LexicalLayer {
  fn name(&self) -> &'static str {
    "lexical"
  }

  fn priority(&self) -> u8 {
    10
  }

  async fn analyse(&self, ctx: &mut RequestContext) -> Result<Decision> {
    // ── Build text corpus ─────────────────────────────────────────────
    // We inspect URI, body, User-Agent, Referer.
    // Each text is paired with its source for accurate match reporting.
    let uri_str = ctx.uri.clone();
    let body_str = std::str::from_utf8(&ctx.body).unwrap_or("").to_string();
    let ua = ctx
      .headers
      .0
      .get("user-agent")
      .and_then(|v| v.to_str().ok())
      .unwrap_or("")
      .to_string();
    let referer = ctx
      .headers
      .0
      .get("referer")
      .and_then(|v| v.to_str().ok())
      .unwrap_or("")
      .to_string();

    let mut texts: Vec<(&str, MatchedIn)> = vec![(&uri_str, MatchedIn::Uri)];
    if !body_str.is_empty() {
      texts.push((&body_str, MatchedIn::Body));
    }
    if !ua.is_empty() {
      texts.push((&ua, MatchedIn::UserAgent));
    }
    if !referer.is_empty() {
      texts.push((&referer, MatchedIn::Referer));
    }

    // ── Scan ──────────────────────────────────────────────────────────
    let result = self.scanner.scan(&texts);

    if result.is_clean {
      debug!(request_id = %ctx.id, "Lexical: clean");
      return Ok(Decision::Allow);
    }

    // ── Process matches ───────────────────────────────────────────────
    let mut worst_category: Option<ThreatCategory> = None;
    let mut worst_pattern = "";

    for threat_match in &result.matches {
      let tag = threat_match.category.as_tag();

      warn!(
          request_id = %ctx.id,
          client_ip  = %ctx.client_ip,
          category   = tag,
          pattern    = threat_match.pattern,
          location   = ?threat_match.matched_in,
          "Lexical threat detected"
      );

      ctx.tag(tag, self.name());
      ctx.add_risk(self.config.risk_delta);

      if worst_category.is_none() {
        worst_category = Some(threat_match.category.clone());
        worst_pattern = threat_match.pattern;
      }
    }

    // ── Decision ──────────────────────────────────────────────────────
    if self.config.block_on_match {
      let category = worst_category.unwrap();
      return Ok(Decision::block(
        format!(
          "Lexical threat detected: {} (pattern: {})",
          category.as_tag(),
          worst_pattern
        ),
        category.block_code(),
      ));
    }

    // Not blocking on match — let risk score decide downstream.
    // The pipeline will block if accumulated risk >= threshold.
    Ok(Decision::Allow)
  }
}
