use nom::branch::alt;
use nom::bytes::complete::{tag, take_while};
use nom::character::complete::{char, digit1, multispace0, multispace1};
use nom::combinator::map;
use nom::error::{Error, ErrorKind};
use nom::sequence::{delimited, tuple};
use nom::IResult;
use once_cell::sync::Lazy;

use crate::ast::AstFinding;
use crate::sql::lexer::normalise;

static STACKED_KEYWORDS: Lazy<[&str; 7]> = Lazy::new(|| {
  [
    "DROP", "DELETE", "INSERT", "UPDATE", "CREATE", "SELECT", "EXEC",
  ]
});

static TIME_PAYLOADS: Lazy<[&str; 4]> =
  Lazy::new(|| ["SLEEP(", "WAITFOR", "BENCHMARK(", "PG_SLEEP("]);

/// Run all SQL injection checks. Returns all findings — empty means clean.
pub fn scan_sql(input: &str) -> Vec<AstFinding> {
  let normalised = normalise(input);
  let mut findings = Vec::new();

  if detect_union(&normalised) {
    findings.push(AstFinding::SqlUnion);
  }
  if detect_stacked(&normalised) {
    findings.push(AstFinding::SqlStacked);
  }
  if detect_tautology(&normalised) {
    findings.push(AstFinding::SqlTautology);
  }
  if detect_time_based(&normalised) {
    findings.push(AstFinding::SqlTimeBased);
  }
  if detect_comment(input) {
    findings.push(AstFinding::SqlCommentStrip);
  }
  if detect_subquery(&normalised) {
    findings.push(AstFinding::SqlSubquery);
  }

  findings
}

fn detect_union(input: &str) -> bool {
  let upper = input.to_uppercase();
  let mut start = 0;

  while let Some(rel) = upper[start..].find("UNION") {
    let union_start = start + rel;
    let union_end = union_start + "UNION".len();

    if !is_keyword_boundary(&upper, union_start, union_end) {
      start = union_end;
      continue;
    }

    let mut suffix = upper[union_end..].trim_start();
    if suffix.starts_with("ALL") {
      suffix = suffix["ALL".len()..].trim_start();
    }

    if suffix.starts_with("SELECT") {
      return true;
    }

    start = union_end;
  }

  false
}

fn detect_stacked(input: &str) -> bool {
  let upper = input.to_uppercase();
  for (idx, _) in upper.match_indices(';') {
    let suffix = upper[idx + 1..].trim_start();
    if STACKED_KEYWORDS
      .iter()
      .any(|kw| starts_with_keyword(suffix, kw))
    {
      return true;
    }
  }
  false
}

fn detect_tautology(input: &str) -> bool {
  let lower = input.to_lowercase();
  for (idx, _) in lower.char_indices() {
    if idx > 0 {
      let prev = lower[..idx].chars().last().unwrap_or(' ');
      if prev.is_ascii_alphanumeric() || prev == '_' {
        continue;
      }
    }

    if parse_tautology_clause(&lower[idx..]).is_ok() {
      return true;
    }
  }
  false
}

fn detect_time_based(input: &str) -> bool {
  let upper = input.to_uppercase();
  TIME_PAYLOADS.iter().any(|m| upper.contains(m))
}

fn detect_comment(input: &str) -> bool {
  if input.contains("/*") || input.contains("--") || input.contains("# ") {
    return true;
  }
  let lower = input.to_ascii_lowercase();
  lower.contains("%23") || lower.contains("%2f%2a")
}

fn detect_subquery(input: &str) -> bool {
  let upper = input.to_uppercase();
  upper.contains("(SELECT") || upper.contains("( SELECT")
}

fn starts_with_keyword(input: &str, keyword: &str) -> bool {
  if !input.starts_with(keyword) {
    return false;
  }

  let next = input[keyword.len()..].chars().next();
  !next.is_some_and(is_word_char)
}

fn is_keyword_boundary(input: &str, start: usize, end: usize) -> bool {
  let prev = if start > 0 {
    input[..start].chars().last()
  } else {
    None
  };
  let next = if end < input.len() {
    input[end..].chars().next()
  } else {
    None
  };

  !prev.is_some_and(is_word_char) && !next.is_some_and(is_word_char)
}

fn is_word_char(ch: char) -> bool {
  ch.is_ascii_alphanumeric() || ch == '_'
}

fn parse_tautology_clause(input: &str) -> IResult<&str, ()> {
  map(
    tuple((parse_logic_op, multispace1, parse_tautology_rhs)),
    |_| (),
  )(input)
}

fn parse_logic_op(input: &str) -> IResult<&str, &str> {
  alt((tag("or"), tag("and")))(input)
}

fn parse_tautology_rhs(input: &str) -> IResult<&str, ()> {
  alt((
    map(parse_numeric_eq, |_| ()),
    map(parse_quoted_eq, |_| ()),
    map(parse_bool_lit, |_| ()),
  ))(input)
}

fn parse_numeric_eq(input: &str) -> IResult<&str, ()> {
  map(
    tuple((digit1, multispace0, char('='), multispace0, digit1)),
    |_| (),
  )(input)
}

fn parse_quoted_eq(input: &str) -> IResult<&str, ()> {
  map(
    tuple((
      parse_quoted_value,
      multispace0,
      char('='),
      multispace0,
      parse_quoted_value,
    )),
    |_| (),
  )(input)
}

fn parse_quoted_value(input: &str) -> IResult<&str, &str> {
  delimited(char('\''), take_while(|c| c != '\''), char('\''))(input)
}

fn parse_bool_lit(input: &str) -> IResult<&str, &str> {
  let (rest, value) = alt((tag("true"), tag("false")))(input)?;
  if rest.chars().next().is_some_and(is_word_char) {
    return Err(nom::Err::Error(Error::new(input, ErrorKind::AlphaNumeric)));
  }
  Ok((rest, value))
}

#[cfg(test)]
mod tests {
  use super::scan_sql;
  use crate::ast::AstFinding;

  #[test]
  fn detects_union_select() {
    let findings = scan_sql("1 UNION SELECT username FROM users");
    assert!(findings.contains(&AstFinding::SqlUnion));
  }

  #[test]
  fn detects_union_all_select() {
    let findings = scan_sql("1 UNION ALL SELECT username FROM users");
    assert!(findings.contains(&AstFinding::SqlUnion));
  }

  #[test]
  fn detects_stacked_drop() {
    let findings = scan_sql("foo; DROP TABLE users");
    assert!(findings.contains(&AstFinding::SqlStacked));
  }

  #[test]
  fn detects_sleep() {
    let findings = scan_sql("1 OR SLEEP(5)");
    assert!(findings.contains(&AstFinding::SqlTimeBased));
  }

  #[test]
  fn detects_subquery() {
    let findings = scan_sql("id=(SELECT id FROM users)");
    assert!(findings.contains(&AstFinding::SqlSubquery));
  }

  #[test]
  fn detects_comment_obfuscation_round_trip() {
    let findings = scan_sql("SE/**/LECT * FROM users");
    assert!(findings.contains(&AstFinding::SqlCommentStrip));
  }

  #[test]
  fn clean_integer_no_findings() {
    let findings = scan_sql("123456");
    assert!(findings.is_empty());
  }

  #[test]
  fn clean_search_query_no_findings() {
    let findings = scan_sql("best rust parser combinator tutorials");
    assert!(findings.is_empty());
  }
}
