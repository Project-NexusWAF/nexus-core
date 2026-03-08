use crate::ast::AstFinding;

#[derive(Debug, Clone)]
pub struct GrammarFinding {
  pub finding: AstFinding,
  pub source: &'static str,
}

pub struct GrammarScanner;

impl GrammarScanner {
  pub fn new() -> Self {
    Self
  }

  /// Scan a list of `(text, source_label)` pairs and deduplicate by `(finding, source)`.
  pub fn scan(&self, inputs: &[(&str, &'static str)]) -> Vec<GrammarFinding> {
    let mut findings = Vec::new();

    for (text, source) in inputs {
      for finding in crate::sql::parser::scan_sql(text) {
        push_unique(&mut findings, finding, source);
      }

      for finding in crate::html::parser::scan_html(text) {
        push_unique(&mut findings, finding, source);
      }
    }

    findings
  }
}

impl Default for GrammarScanner {
  fn default() -> Self {
    Self::new()
  }
}

fn push_unique(findings: &mut Vec<GrammarFinding>, finding: AstFinding, source: &'static str) {
  if findings
    .iter()
    .any(|existing| existing.source == source && existing.finding == finding)
  {
    return;
  }

  findings.push(GrammarFinding { finding, source });
}

#[cfg(test)]
mod tests {
  use super::GrammarScanner;
  use crate::ast::AstFinding;

  #[test]
  fn scan_multiple_inputs() {
    let scanner = GrammarScanner::new();
    let findings = scanner.scan(&[
      ("1 UNION SELECT username FROM users", "uri"),
      ("<script>alert(1)</script>", "body"),
    ]);

    assert!(findings
      .iter()
      .any(|f| f.source == "uri" && f.finding == AstFinding::SqlUnion));
    assert!(findings
      .iter()
      .any(|f| f.source == "body" && f.finding == AstFinding::HtmlScriptTag));
  }

  #[test]
  fn clean_request_no_findings() {
    let scanner = GrammarScanner::new();
    let findings = scanner.scan(&[("/search?q=rust", "uri"), ("hello world", "body")]);
    assert!(findings.is_empty());
  }

  #[test]
  fn deduplication() {
    let scanner = GrammarScanner::new();
    let findings = scanner.scan(&[
      ("1 UNION SELECT username FROM users", "uri"),
      ("2 UNION SELECT email FROM users", "uri"),
    ]);

    let union_hits = findings
      .iter()
      .filter(|f| f.source == "uri" && f.finding == AstFinding::SqlUnion)
      .count();

    assert_eq!(union_hits, 1);
  }
}
