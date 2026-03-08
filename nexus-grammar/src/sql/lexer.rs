/// Strip SQL comments and collapse whitespace so structural parsing sees stable tokens.
pub fn normalise(input: &str) -> String {
  let mut out = String::with_capacity(input.len());
  let mut i = 0;

  while i < input.len() {
    let rest = &input[i..];

    if rest.starts_with("/*") {
      i += 2;
      while i < input.len() {
        let comment_rest = &input[i..];
        if comment_rest.starts_with("*/") {
          i += 2;
          break;
        }
        let Some(ch) = comment_rest.chars().next() else {
          break;
        };
        i += ch.len_utf8();
      }
      emit_space(&mut out);
      continue;
    }

    if rest.starts_with("--") {
      i += 2;
      while i < input.len() {
        let Some(ch) = input[i..].chars().next() else {
          break;
        };
        i += ch.len_utf8();
        if ch == '\n' {
          break;
        }
      }
      emit_space(&mut out);
      continue;
    }

    if rest.starts_with('#') {
      i += 1;
      while i < input.len() {
        let Some(ch) = input[i..].chars().next() else {
          break;
        };
        i += ch.len_utf8();
        if ch == '\n' {
          break;
        }
      }
      emit_space(&mut out);
      continue;
    }

    let Some(ch) = rest.chars().next() else {
      break;
    };

    if ch.is_whitespace() {
      i += ch.len_utf8();
      while i < input.len() {
        let Some(next) = input[i..].chars().next() else {
          break;
        };
        if !next.is_whitespace() {
          break;
        }
        i += next.len_utf8();
      }
      emit_space(&mut out);
      continue;
    }

    out.push(ch);
    i += ch.len_utf8();
  }

  out.trim().to_string()
}

fn emit_space(out: &mut String) {
  if !out.is_empty() && !out.ends_with(' ') {
    out.push(' ');
  }
}

#[cfg(test)]
mod tests {
  use super::normalise;

  #[test]
  fn strips_inline_block_comment() {
    let raw = "SE/**/LECT * FROM users";
    assert_eq!(normalise(raw), "SE LECT * FROM users");
  }

  #[test]
  fn strips_line_comment() {
    let raw = "1 OR 1=1 -- comment";
    assert_eq!(normalise(raw), "1 OR 1=1");
  }

  #[test]
  fn strips_hash_comment() {
    let raw = "SELECT 1 # comment\nFROM dual";
    assert_eq!(normalise(raw), "SELECT 1 FROM dual");
  }

  #[test]
  fn collapses_whitespace() {
    let raw = "SELECT   \n\t   1";
    assert_eq!(normalise(raw), "SELECT 1");
  }

  #[test]
  fn clean_passthrough() {
    let raw = "SELECT id FROM users";
    assert_eq!(normalise(raw), raw);
  }
}
