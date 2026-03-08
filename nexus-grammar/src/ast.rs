use nexus_common::BlockCode;

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AstFinding {
  SqlTautology,
  SqlUnion,
  SqlStacked,
  SqlTimeBased,
  SqlCommentStrip,
  SqlSubquery,
  HtmlScriptTag,
  HtmlEventHandler,
  HtmlJavascriptUri,
  HtmlDanglingMarkup,
}

impl AstFinding {
  pub fn as_tag(&self) -> &'static str {
    match self {
      AstFinding::SqlTautology
      | AstFinding::SqlUnion
      | AstFinding::SqlStacked
      | AstFinding::SqlTimeBased
      | AstFinding::SqlCommentStrip
      | AstFinding::SqlSubquery => "sqli",
      AstFinding::HtmlScriptTag
      | AstFinding::HtmlEventHandler
      | AstFinding::HtmlJavascriptUri
      | AstFinding::HtmlDanglingMarkup => "xss",
    }
  }

  pub fn description(&self) -> &'static str {
    match self {
      AstFinding::SqlTautology => "SQL tautology predicate",
      AstFinding::SqlUnion => "SQL UNION SELECT structure",
      AstFinding::SqlStacked => "Stacked SQL statement after semicolon",
      AstFinding::SqlTimeBased => "Time-based SQL function usage",
      AstFinding::SqlCommentStrip => "SQL comment obfuscation marker",
      AstFinding::SqlSubquery => "Nested SQL subquery payload",
      AstFinding::HtmlScriptTag => "HTML script tag structure",
      AstFinding::HtmlEventHandler => "Inline HTML event handler attribute",
      AstFinding::HtmlJavascriptUri => "Executable URI scheme in HTML context",
      AstFinding::HtmlDanglingMarkup => "Dangling markup pattern",
    }
  }

  pub fn block_code(&self) -> BlockCode {
    match self {
      AstFinding::SqlTautology
      | AstFinding::SqlUnion
      | AstFinding::SqlStacked
      | AstFinding::SqlTimeBased
      | AstFinding::SqlCommentStrip
      | AstFinding::SqlSubquery => BlockCode::SqlInjection,
      AstFinding::HtmlScriptTag
      | AstFinding::HtmlEventHandler
      | AstFinding::HtmlJavascriptUri
      | AstFinding::HtmlDanglingMarkup => BlockCode::CrossSiteScripting,
    }
  }

  pub fn risk_delta(&self) -> f32 {
    match self {
      AstFinding::SqlUnion
      | AstFinding::SqlStacked
      | AstFinding::HtmlScriptTag
      | AstFinding::HtmlEventHandler => 0.6,
      AstFinding::SqlTautology | AstFinding::SqlSubquery | AstFinding::HtmlJavascriptUri => 0.4,
      AstFinding::SqlTimeBased | AstFinding::SqlCommentStrip | AstFinding::HtmlDanglingMarkup => {
        0.3
      }
    }
  }

  pub fn severity_rank(&self) -> u8 {
    match self {
      AstFinding::SqlUnion | AstFinding::SqlStacked => 6,
      AstFinding::HtmlScriptTag | AstFinding::HtmlEventHandler => 5,
      AstFinding::SqlTautology | AstFinding::SqlSubquery | AstFinding::HtmlJavascriptUri => 4,
      AstFinding::SqlTimeBased => 3,
      AstFinding::SqlCommentStrip => 2,
      AstFinding::HtmlDanglingMarkup => 1,
    }
  }
}
