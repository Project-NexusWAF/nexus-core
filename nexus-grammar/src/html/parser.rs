use crate::ast::AstFinding;

/// Scan for structural HTML/XSS patterns.
pub fn scan_html(input: &str) -> Vec<AstFinding> {
  let normalised = normalise_html(input);
  let mut findings = Vec::new();

  if detect_script_tag(&normalised) {
    findings.push(AstFinding::HtmlScriptTag);
  }
  if detect_event_handler(&normalised) {
    findings.push(AstFinding::HtmlEventHandler);
  }
  if detect_js_uri(&normalised) {
    findings.push(AstFinding::HtmlJavascriptUri);
  }
  if detect_dangling(&normalised) {
    findings.push(AstFinding::HtmlDanglingMarkup);
  }

  findings
}

fn normalise_html(input: &str) -> String {
  let mut decoded = String::with_capacity(input.len());
  let bytes = input.as_bytes();
  let mut i = 0;

  while i < bytes.len() {
    if bytes[i] == b'%' && i + 2 < bytes.len() {
      let h1 = hex_value(bytes[i + 1]);
      let h2 = hex_value(bytes[i + 2]);
      if let (Some(a), Some(b)) = (h1, h2) {
        let value = (a << 4) | b;
        decoded.push(value as char);
        i += 3;
        continue;
      }
    }

    let rest = &input[i..];
    let Some(ch) = rest.chars().next() else {
      break;
    };
    decoded.push(ch);
    i += ch.len_utf8();
  }

  decoded.retain(|c| c != '\0');
  decoded.to_lowercase()
}

fn hex_value(b: u8) -> Option<u8> {
  match b {
    b'0'..=b'9' => Some(b - b'0'),
    b'a'..=b'f' => Some(10 + b - b'a'),
    b'A'..=b'F' => Some(10 + b - b'A'),
    _ => None,
  }
}

fn detect_script_tag(input: &str) -> bool {
  if input.contains("<script") || input.contains("</script") {
    return true;
  }

  let stripped: String = input
    .chars()
    .filter(|c| c.is_ascii_alphanumeric() || matches!(*c, '<' | '>' | '/'))
    .collect();
  stripped.contains("<script") || stripped.contains("</script")
}

fn detect_event_handler(input: &str) -> bool {
  let chars: Vec<char> = input.chars().collect();
  if chars.len() < 4 {
    return false;
  }

  for i in 0..(chars.len() - 1) {
    if chars[i] != 'o' || chars[i + 1] != 'n' {
      continue;
    }

    let prev_ok = if i == 0 {
      true
    } else {
      let prev = chars[i - 1];
      prev.is_whitespace() || prev == '<' || prev == '"' || prev == '\''
    };
    if !prev_ok {
      continue;
    }

    let mut j = i + 2;
    while j < chars.len() && chars[j].is_ascii_alphabetic() {
      j += 1;
    }
    if j == i + 2 {
      continue;
    }

    while j < chars.len() && chars[j].is_whitespace() {
      j += 1;
    }

    if j < chars.len() && chars[j] == '=' {
      return true;
    }
  }

  false
}

fn detect_js_uri(input: &str) -> bool {
  let compact: String = input.chars().filter(|c| !c.is_whitespace()).collect();
  compact.contains("javascript:")
    || compact.contains("vbscript:")
    || compact.contains("data:text/html")
}

fn detect_dangling(input: &str) -> bool {
  let opens = input.chars().filter(|c| *c == '<').count();
  let closes = input.chars().filter(|c| *c == '>').count();
  opens > closes && (input.contains("http") || input.contains("href"))
}

#[cfg(test)]
mod tests {
  use super::scan_html;
  use crate::ast::AstFinding;

  #[test]
  fn detects_script_tag() {
    let findings = scan_html("<script>alert(1)</script>");
    assert!(findings.contains(&AstFinding::HtmlScriptTag));
  }

  #[test]
  fn detects_uppercase_script_tag() {
    let findings = scan_html("<SCRIPT>alert(1)</SCRIPT>");
    assert!(findings.contains(&AstFinding::HtmlScriptTag));
  }

  #[test]
  fn detects_percent_encoded_script_tag() {
    let findings = scan_html("%3cscript%3ealert(1)%3c/script%3e");
    assert!(findings.contains(&AstFinding::HtmlScriptTag));
  }

  #[test]
  fn detects_onerror_handler() {
    let findings = scan_html(r#"<img src=x onerror=alert(1)>"#);
    assert!(findings.contains(&AstFinding::HtmlEventHandler));
  }

  #[test]
  fn detects_onload_handler() {
    let findings = scan_html(r#"<body onload=doBadThing()>"#);
    assert!(findings.contains(&AstFinding::HtmlEventHandler));
  }

  #[test]
  fn detects_javascript_uri() {
    let findings = scan_html(r#"<a href="javascript:alert(1)">click</a>"#);
    assert!(findings.contains(&AstFinding::HtmlJavascriptUri));
  }

  #[test]
  fn detects_vbscript_uri() {
    let findings = scan_html(r#"<a href="vbscript:msgbox(1)">click</a>"#);
    assert!(findings.contains(&AstFinding::HtmlJavascriptUri));
  }

  #[test]
  fn clean_paragraph_no_findings() {
    let findings = scan_html("<p>Hello</p>");
    assert!(findings.is_empty());
  }

  #[test]
  fn clean_plain_text_no_findings() {
    let findings = scan_html("safe plain text with no markup");
    assert!(findings.is_empty());
  }
}
