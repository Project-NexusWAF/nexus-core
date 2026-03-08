use nexus_config::LexicalConfig;

use crate::patterns::{
  CMD_INJECTION_NAMED, CMD_INJECTION_SET, EVASION_SET, PATH_TRAVERSAL_NAMED, PATH_TRAVERSAL_SET,
  SQLI_NAMED, SQLI_SET, XSS_NAMED, XSS_SET,
};

/// A single threat match from the lexical scanner.
#[derive(Debug, Clone, PartialEq)]
pub struct ThreatMatch {
  /// Category of threat detected.
  pub category: ThreatCategory,

  /// The specific pattern name that fired.
  pub pattern: &'static str,

  /// The text that triggered the match (truncated for safety).
  pub matched_in: MatchedIn,
}

/// Which part of the request triggered the match.
#[derive(Debug, Clone, PartialEq)]
pub enum MatchedIn {
  Uri,
  Body,
  UserAgent,
  Referer,
  Header(String),
}

/// Threat category from the lexical layer.
#[derive(Debug, Clone, PartialEq)]
pub enum ThreatCategory {
  SqlInjection,
  CrossSiteScripting,
  PathTraversal,
  CommandInjection,
  Evasion,
}

impl ThreatCategory {
  /// Numeric severity rank — higher is more dangerous.
  /// Used by the layer to pick the worst match across all findings.
  ///
  /// Ranking rationale:
  ///   CommandInjection (4) — direct OS code execution, highest impact
  ///   SqlInjection     (3) — data exfiltration / destruction
  ///   CrossSiteScripting (2) — client-side code execution
  ///   PathTraversal    (1) — file-system read, limited to server files
  ///   Evasion          (0) — encoding trick, no direct payload impact
  pub fn severity(&self) -> u8 {
    match self {
      ThreatCategory::CommandInjection => 4,
      ThreatCategory::SqlInjection => 3,
      ThreatCategory::CrossSiteScripting => 2,
      ThreatCategory::PathTraversal => 1,
      ThreatCategory::Evasion => 0,
    }
  }

  pub fn as_tag(&self) -> &'static str {
    match self {
      ThreatCategory::SqlInjection => "sqli",
      ThreatCategory::CrossSiteScripting => "xss",
      ThreatCategory::PathTraversal => "path_traversal",
      ThreatCategory::CommandInjection => "cmd_injection",
      ThreatCategory::Evasion => "evasion",
    }
  }

  pub fn block_code(&self) -> nexus_common::BlockCode {
    use nexus_common::BlockCode;
    match self {
      ThreatCategory::SqlInjection => BlockCode::SqlInjection,
      ThreatCategory::CrossSiteScripting => BlockCode::CrossSiteScripting,
      ThreatCategory::PathTraversal => BlockCode::PathTraversal,
      ThreatCategory::CommandInjection => BlockCode::CommandInjection,
      ThreatCategory::Evasion => BlockCode::ProtocolViolation,
    }
  }
}

/// The result of scanning one request.
#[derive(Debug, Default)]
pub struct ScanResult {
  pub matches: Vec<ThreatMatch>,
  pub is_clean: bool,
}

impl ScanResult {
  pub fn clean() -> Self {
    Self {
      matches: vec![],
      is_clean: true,
    }
  }

  pub fn threat(matches: Vec<ThreatMatch>) -> Self {
    Self {
      is_clean: matches.is_empty(),
      matches,
    }
  }
}

/// Stateless scanner — holds no per-request state.
/// Construct once, call `scan()` from many concurrent tasks.
pub struct LexicalScanner {
  config: LexicalConfig,
}

impl LexicalScanner {
  pub fn new(config: LexicalConfig) -> Self {
    // Force pattern compilation at construction time (not first request)
    // by touching all the Lazy statics.
    let _ = &*SQLI_SET;
    let _ = &*XSS_SET;
    let _ = &*PATH_TRAVERSAL_SET;
    let _ = &*CMD_INJECTION_SET;
    let _ = &*EVASION_SET;
    Self { config }
  }

  /// Scan all inspectable text in the request context.
  /// Returns a `ScanResult` with all matches found.
  pub fn scan(&self, texts: &[(&str, MatchedIn)]) -> ScanResult {
    let mut matches = Vec::new();

    for (text, location) in texts {
      if text.is_empty() {
        continue;
      }

      if self.config.sqli_enabled {
        self.scan_category(
          text,
          location,
          &SQLI_SET,
          &SQLI_NAMED,
          ThreatCategory::SqlInjection,
          &mut matches,
        );
      }

      if self.config.xss_enabled {
        self.scan_category(
          text,
          location,
          &XSS_SET,
          &XSS_NAMED,
          ThreatCategory::CrossSiteScripting,
          &mut matches,
        );
      }

      if self.config.path_traversal_enabled {
        self.scan_category(
          text,
          location,
          &PATH_TRAVERSAL_SET,
          &PATH_TRAVERSAL_NAMED,
          ThreatCategory::PathTraversal,
          &mut matches,
        );
      }

      if self.config.cmd_injection_enabled {
        self.scan_category(
          text,
          location,
          &CMD_INJECTION_SET,
          &CMD_INJECTION_NAMED,
          ThreatCategory::CommandInjection,
          &mut matches,
        );
      }

      // Always check evasion (it's cheap and catches encoding tricks)
      if !EVASION_SET.is_match(text) {
        // fast path — no evasion
      } else {
        matches.push(ThreatMatch {
          category: ThreatCategory::Evasion,
          pattern: "evasion_encoding",
          matched_in: location.clone(),
        });
      }
    }

    ScanResult::threat(matches)
  }

  /// Scan `text` against a RegexSet (fast multi-pattern scan), then
  /// use named patterns to identify which specific patterns fired.
  fn scan_category(
    &self,
    text: &str,
    location: &MatchedIn,
    set: &regex::RegexSet,
    named: &[(&'static str, regex::Regex)],
    category: ThreatCategory,
    matches: &mut Vec<ThreatMatch>,
  ) {
    // First: fast set scan — single pass over text for ALL patterns.
    // If nothing matches, we're done (common case for clean traffic).
    if !set.is_match(text) {
      return;
    }

    // Something matched — find which named pattern(s) fired.
    // This second pass only happens on suspicious traffic.
    let mut found_named_match = false;
    for (pattern_name, regex) in named.iter() {
      if regex.is_match(text) {
        matches.push(ThreatMatch {
          category: category.clone(),
          pattern: pattern_name,
          matched_in: location.clone(),
        });
        // One match per category per location is sufficient for
        // reporting purposes — we don't need every matching pattern.
        found_named_match = true;
        break;
      }
    }

    // The RegexSet fired but no named pattern claimed the match.
    // This happens when the SET contains patterns that have no named
    // counterpart (e.g. file I/O, system-table probing for SQLi, or
    // iframe/SVG vectors for XSS). We must not silently drop the hit,
    // so we push a sentinel ThreatMatch that preserves the category
    // and location so downstream layers can still act on it.
    if !found_named_match {
      matches.push(ThreatMatch {
        category,
        pattern: "unknown_pattern",
        matched_in: location.clone(),
      });
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use nexus_config::LexicalConfig;

  fn scanner() -> LexicalScanner {
    LexicalScanner::new(LexicalConfig {
      sqli_enabled: true,
      xss_enabled: true,
      path_traversal_enabled: true,
      cmd_injection_enabled: true,
      risk_delta: 0.4,
      block_on_match: false,
    })
  }

  fn scan_uri(s: &str) -> ScanResult {
    scanner().scan(&[(s, MatchedIn::Uri)])
  }

  fn scan_body(s: &str) -> ScanResult {
    scanner().scan(&[(s, MatchedIn::Body)])
  }

  // ── SQLi ──────────────────────────────────────────────────────────────
  #[test]
  fn detects_tautology_sqli() {
    let r = scan_uri("' OR 1=1 --");
    assert!(!r.is_clean);
    assert!(r
      .matches
      .iter()
      .any(|m| m.category == ThreatCategory::SqlInjection));
  }

  #[test]
  fn detects_union_select() {
    let r = scan_uri("/search?q=1 UNION SELECT username,password FROM users");
    assert!(!r.is_clean);
    assert!(r.matches.iter().any(|m| m.pattern == "sqli_union_select"));
  }

  #[test]
  fn detects_sleep_blind() {
    let r = scan_body("id=1; SLEEP(5)--");
    assert!(!r.is_clean);
    assert!(r.matches.iter().any(|m| m.pattern == "sqli_time_blind"));
  }

  #[test]
  fn detects_stacked_query() {
    let r = scan_body("name=foo; DROP TABLE users; --");
    assert!(!r.is_clean);
    assert!(r
      .matches
      .iter()
      .any(|m| m.category == ThreatCategory::SqlInjection));
  }

  // ── XSS ───────────────────────────────────────────────────────────────
  #[test]
  fn detects_script_tag() {
    let r = scan_body("<script>alert(1)</script>");
    assert!(!r.is_clean);
    assert!(r.matches.iter().any(|m| m.pattern == "xss_script_tag"));
  }

  #[test]
  fn detects_event_handler() {
    let r = scan_uri("/page?name=<img onerror=alert(1)>");
    assert!(!r.is_clean);
    assert!(r.matches.iter().any(|m| m.pattern == "xss_event_handler"));
  }

  #[test]
  fn detects_javascript_uri() {
    let r = scan_uri("/redirect?to=javascript:alert(document.cookie)");
    assert!(!r.is_clean);
    assert!(r.matches.iter().any(|m| m.pattern == "xss_javascript_uri"));
  }

  #[test]
  fn detects_template_injection() {
    let r = scan_body("name={{7*7}}");
    assert!(!r.is_clean);
    assert!(r.matches.iter().any(|m| m.pattern == "xss_template_inj"));
  }

  // ── Path Traversal ────────────────────────────────────────────────────
  #[test]
  fn detects_dotdot_slash() {
    let r = scan_uri("/files/../../etc/passwd");
    assert!(!r.is_clean);
    assert!(r
      .matches
      .iter()
      .any(|m| m.category == ThreatCategory::PathTraversal));
  }

  #[test]
  fn detects_encoded_traversal() {
    let r = scan_uri("/files/%2e%2e%2fetc%2fpasswd");
    assert!(!r.is_clean);
    assert!(r.matches.iter().any(|m| m.pattern == "traversal_encoded"));
  }

  #[test]
  fn detects_etc_passwd_direct() {
    let r = scan_uri("/etc/passwd");
    assert!(!r.is_clean);
  }

  // ── Command Injection ─────────────────────────────────────────────────
  #[test]
  fn detects_shell_operator() {
    let r = scan_body("filename=test.txt; cat /etc/passwd");
    assert!(!r.is_clean);
    assert!(r
      .matches
      .iter()
      .any(|m| m.category == ThreatCategory::CommandInjection));
  }

  #[test]
  fn detects_subshell() {
    let r = scan_body("host=$(cat /etc/passwd)");
    assert!(!r.is_clean);
    assert!(r.matches.iter().any(|m| m.pattern == "cmdi_subshell"));
  }

  #[test]
  fn detects_backtick() {
    let r = scan_body("user=`id`");
    assert!(!r.is_clean);
    assert!(r.matches.iter().any(|m| m.pattern == "cmdi_backtick"));
  }

  // ── Clean traffic ─────────────────────────────────────────────────────
  #[test]
  fn clean_search_query_passes() {
    let r = scan_uri("/search?q=best+rust+web+frameworks");
    assert!(r.is_clean, "Clean search query should not be flagged");
  }

  #[test]
  fn clean_json_body_passes() {
    let r = scan_body(r#"{"user":"alice","email":"alice@example.com","age":30}"#);
    assert!(r.is_clean, "Clean JSON should not be flagged");
  }

  #[test]
  fn clean_form_post_passes() {
    let r = scan_body("username=alice&password=hunter2&remember=true");
    assert!(r.is_clean, "Normal form post should not be flagged");
  }

  // ── Evasion ───────────────────────────────────────────────────────────
  #[test]
  fn detects_double_url_encoding() {
    let r = scan_uri("/page?x=%2527");
    assert!(!r.is_clean);
  }
}
