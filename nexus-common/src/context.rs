use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use http::{HeaderMap, Method, Uri, Version};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct MethodWrapper(pub Method);

#[derive(Debug, Clone)]
pub struct VersionWrapper(pub Version);

#[derive(Debug, Clone)]
pub struct HeadersWrapper(pub HeaderMap);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ContentType {
  Json,
  FormUrlEncoded,
  Multipart,
  Xml,
  PlainText,
  Other(String),
}

#[derive(Debug, Clone)]
pub struct RequestContext {
  pub id: Uuid,
  pub recieved_at: DateTime<Utc>,
  pub started_at: Instant,
  pub client_ip: IpAddr,
  pub upstream_host: Option<String>,

  pub method: MethodWrapper,
  pub uri: String,
  pub version: VersionWrapper,
  pub headers: HeadersWrapper,

  pub body: Bytes,
  pub query_params: HashMap<String, String>,
  pub path_segments: Vec<String>,
  pub content_type: Option<ContentType>,

  pub threat_tags: Vec<String>,
  pub risk_score: f32,

  pub flagged_by: Option<String>,

  pub rate_limited: bool,
  pub rate_limit_remaining: Option<u32>,

  pub ml_score: Option<f32>,
  pub ml_label: Option<String>,

  pub meta: HashMap<String, String>,
}

impl RequestContext {
  pub fn new(
    client_ip: IpAddr,
    method: Method,
    uri: Uri,
    version: Version,
    headers: HeaderMap,
    body: Bytes,
  ) -> RequestContext {
    let uri_str = uri.to_string();
    let query_params = parse_query(uri.query().unwrap_or(""));
    let path_segments = parse_path_segments(uri.path());
    let content_type = extract_content_type(&headers);

    Self {
      id: Uuid::new_v4(),
      recieved_at: Utc::now(),
      started_at: Instant::now(),
      client_ip,
      upstream_host: None,
      method: MethodWrapper(method),
      uri: uri_str,
      version: VersionWrapper(version),
      headers: HeadersWrapper(headers),
      body,
      query_params,
      path_segments,
      content_type,
      threat_tags: Vec::new(),
      risk_score: 0.0,
      flagged_by: None,
      rate_limited: false,
      rate_limit_remaining: None,
      ml_score: None,
      ml_label: None,
      meta: HashMap::new(),
    }
  }

  pub fn tag(&mut self, tag: impl Into<String>, layer: impl Into<String>) {
    let tag = tag.into();

    if !self.threat_tags.contains(&tag) {
      self.threat_tags.push(tag);
    }
    if self.flagged_by.is_none() {
      self.flagged_by = Some(layer.into());
    }
  }

  pub fn add_risk(&mut self, delta: f32) {
    self.risk_score = (self.risk_score + delta).min(1.0);
  }

  pub fn elapsed(&self) -> u64 {
    self.started_at.elapsed().as_micros() as u64
  }

  pub fn has_body(&self) -> bool {
    !self.body.is_empty()
  }

  pub fn analysable_text(&self) -> Vec<&str> {
    let mut texts = vec![self.uri.as_str()];
    if let Ok(body_str) = std::str::from_utf8(&self.body) {
      texts.push(body_str);
    }

    if let Some(ua) = self
      .headers
      .0
      .get("user-agent")
      .and_then(|v| v.to_str().ok())
    {
      texts.push(ua);
    }

    if let Some(referer) = self.headers.0.get("referer").and_then(|v| v.to_str().ok()) {
      texts.push(referer);
    }
    texts
  }
}

fn parse_path_segments(path: &str) -> Vec<String> {
  path
    .split('/')
    .filter(|segment| !segment.is_empty())
    .map(|s| s.to_string())
    .collect()
}

fn extract_content_type(headers: &HeaderMap) -> Option<ContentType> {
  let ct = headers.get("content-type")?.to_str().ok()?;
  let ct_lower = ct.to_lowercase();
  Some(if ct_lower.contains("application/json") {
    ContentType::Json
  } else if ct_lower.contains("application/x-www-form-urlencoded") {
    ContentType::FormUrlEncoded
  } else if ct_lower.contains("multipart/form-data") {
    ContentType::Multipart
  } else if ct_lower.contains("application/xml") || ct_lower.contains("text/xml") {
    ContentType::Xml
  } else if ct_lower.contains("text/plain") {
    ContentType::PlainText
  } else {
    ContentType::Other(ct.to_string())
  })
}

fn parse_query(query: &str) -> HashMap<String, String> {
  if query.is_empty() {
    return HashMap::new();
  }
  query
    .split('&')
    .filter_map(|pair| {
      let mut it = pair.splitn(2, '=');
      let key = it.next()?.to_string();
      let val = it.next().unwrap_or("").to_string();
      Some((urlencoding_decode(&key), urlencoding_decode(&val)))
    })
    .collect()
}

fn urlencoding_decode(s: &str) -> String {
  let mut result = String::with_capacity(s.len());
  let mut chars = s.chars().peekable();

  while let Some(c) = chars.next() {
    match c {
      '%' => {
        let h1 = chars.next().unwrap_or('0');
        let h2 = chars.next().unwrap_or('0');
        if let Ok(byte) = u8::from_str_radix(&format!("{h1}{h2}"), 16) {
          result.push(byte as char);
        } else {
          result.push('%');
          result.push(h1);
          result.push(h2);
        }
      }
      '+' => result.push(' '),
      _ => result.push(c),
    }
  }
  result
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::Ipv4Addr;

  fn make_ctx(uri: &str) -> RequestContext {
    RequestContext::new(
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
      Method::GET,
      uri.parse().unwrap(),
      Version::HTTP_11,
      HeaderMap::new(),
      Bytes::new(),
    )
  }

  #[test]
  fn parses_query_params() {
    let ctx = make_ctx("http://example.com/search?q=hello+world&page=2");
    assert_eq!(ctx.query_params.get("q"), Some(&"hello world".to_string()));
    assert_eq!(ctx.query_params.get("page"), Some(&"2".to_string()));
  }

  #[test]
  fn parses_path_segments() {
    let ctx = make_ctx("http://example.com/api/v1/users");
    assert_eq!(ctx.path_segments, vec!["api", "v1", "users"]);
  }

  #[test]
  fn tag_is_idempotent() {
    let mut ctx = make_ctx("http://example.com/");
    ctx.tag("sqli", "lexical");
    ctx.tag("sqli", "grammar"); // duplicate — should not add again
    assert_eq!(ctx.threat_tags.len(), 1);
    assert_eq!(ctx.flagged_by, Some("lexical".to_string())); // first tagger wins
  }

  #[test]
  fn risk_score_clamped() {
    let mut ctx = make_ctx("http://example.com/");
    ctx.add_risk(0.7);
    ctx.add_risk(0.7);
    assert_eq!(ctx.risk_score, 1.0); // clamped, not 1.4
  }
}
