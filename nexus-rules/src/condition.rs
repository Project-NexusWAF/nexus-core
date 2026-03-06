use dashmap::DashMap;
use http::Method;
use nexus_common::RequestContext;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::net::IpAddr;
use std::sync::Arc;

/// Pre-parsed CIDR range for efficient IP matching
#[derive(Debug, Clone)]
pub struct ParsedCidr {
  network: IpAddr,
  prefix_len: u8,
}

impl ParsedCidr {
  /// Parse a CIDR string (e.g., "192.168.0.0/24") into a structured format
  pub fn parse(cidr: &str) -> Option<Self> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
      return None;
    }

    let network: IpAddr = parts[0].parse().ok()?;
    let prefix_len: u8 = parts[1].parse().ok()?;

    // Validate prefix length
    match network {
      IpAddr::V4(_) if prefix_len > 32 => return None,
      IpAddr::V6(_) if prefix_len > 128 => return None,
      _ => {}
    }

    Some(Self {
      network,
      prefix_len,
    })
  }

  /// Check if an IP address is within this CIDR range
  pub fn contains(&self, ip: &IpAddr) -> bool {
    match (ip, self.network) {
      (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
        if self.prefix_len == 0 {
          return true;
        }
        let ip_bits = u32::from(*ip4);
        let net_bits = u32::from(net4);
        let mask = !0u32 << (32 - self.prefix_len);
        (ip_bits & mask) == (net_bits & mask)
      }
      (IpAddr::V6(ip6), IpAddr::V6(net6)) => {
        if self.prefix_len == 0 {
          return true;
        }
        let ip_bits = u128::from(*ip6);
        let net_bits = u128::from(net6);
        let mask = !0u128 << (128 - self.prefix_len);
        (ip_bits & mask) == (net_bits & mask)
      }
      _ => false, // Mixed IP versions
    }
  }
}

impl Serialize for ParsedCidr {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let cidr_str = format!("{}/{}", self.network, self.prefix_len);
    serializer.serialize_str(&cidr_str)
  }
}

impl<'de> Deserialize<'de> for ParsedCidr {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    let s = String::deserialize(deserializer)?;
    ParsedCidr::parse(&s)
      .ok_or_else(|| serde::de::Error::custom(format!("Invalid CIDR format: {}", s)))
  }
}

/// A condition that can be evaluated against a request
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
  /// Match if URI starts with the given prefix
  PathPrefix { value: String },

  /// Match if path (without query string) equals the given value
  PathExact { value: String },

  /// Match if HTTP method is in the list
  MethodIs {
    #[serde(
      serialize_with = "serialize_methods",
      deserialize_with = "deserialize_methods"
    )]
    methods: Vec<Method>,
  },

  /// Match if a header contains a specific value (case-insensitive)
  HeaderContains { header: String, value: String },

  /// Match if client IP is in any of the CIDR ranges
  IpInRange { cidrs: Vec<ParsedCidr> },

  /// Match if risk score exceeds threshold
  RiskAbove { threshold: f32 },

  /// Match if request has a specific threat tag
  HasTag { tag: String },

  /// Match if all sub-conditions match
  And { conditions: Vec<Condition> },

  /// Match if any sub-condition matches
  Or { conditions: Vec<Condition> },

  /// Match if sub-condition does NOT match
  Not { condition: Box<Condition> },

  /// Match using regex on a target field
  RegexMatch { target: String, pattern: String },
}

impl Condition {
  /// Evaluate this condition against a request context
  pub fn matches(&self, ctx: &RequestContext) -> bool {
    match self {
      Self::PathPrefix { value } => ctx.path.starts_with(value),

      Self::PathExact { value } => &ctx.path == value,

      Self::MethodIs { methods } => methods.contains(&ctx.method.0),

      Self::HeaderContains { header, value } => {
        if let Some(header_value) = ctx.headers.0.get(header) {
          if let Ok(header_str) = header_value.to_str() {
            return header_str.to_lowercase().contains(&value.to_lowercase());
          }
        }
        false
      }

      Self::IpInRange { cidrs } => cidrs.iter().any(|cidr| cidr.contains(&ctx.client_ip)),

      Self::RiskAbove { threshold } => ctx.risk_score > *threshold,

      Self::HasTag { tag } => ctx.threat_tags.contains(tag),

      Self::And { conditions } => conditions.iter().all(|c| c.matches(ctx)),

      Self::Or { conditions } => conditions.iter().any(|c| c.matches(ctx)),

      Self::Not { condition } => !condition.matches(ctx),

      Self::RegexMatch { target, pattern } => match_regex(ctx, target, pattern),
    }
  }
}

/// Serialize HTTP methods to strings
fn serialize_methods<S>(methods: &[Method], serializer: S) -> Result<S::Ok, S::Error>
where
  S: Serializer,
{
  use serde::ser::SerializeSeq;
  let mut seq = serializer.serialize_seq(Some(methods.len()))?;
  for method in methods {
    seq.serialize_element(method.as_str())?;
  }
  seq.end()
}

/// Deserialize HTTP methods from strings
fn deserialize_methods<'de, D>(deserializer: D) -> Result<Vec<Method>, D::Error>
where
  D: Deserializer<'de>,
{
  let strings: Vec<String> = Vec::deserialize(deserializer)?;
  strings
    .into_iter()
    .map(|s| {
      s.parse::<Method>()
        .map_err(|_| serde::de::Error::custom(format!("Invalid HTTP method: {}", s)))
    })
    .collect()
}

// Global regex cache using DashMap for lock-free concurrent access
static REGEX_CACHE: Lazy<DashMap<String, Option<Arc<Regex>>>> = Lazy::new(DashMap::new);

/// Match a regex pattern against a target field
fn match_regex(ctx: &RequestContext, target: &str, pattern: &str) -> bool {
  // Get or compile and cache the regex
  let re = REGEX_CACHE
    .entry(pattern.to_string())
    .or_insert_with(|| Regex::new(pattern).ok().map(Arc::new))
    .clone();

  // Return false if regex compilation failed
  let re = match re {
    Some(r) => r,
    None => return false,
  };

  let text = match target {
    "uri" => Some(ctx.uri.as_str()),
    "body" => std::str::from_utf8(&ctx.body).ok(),
    s if s.starts_with("header:") => {
      let header_name = &s[7..];
      ctx.headers.0.get(header_name).and_then(|v| v.to_str().ok())
    }
    _ => None,
  };

  text.map(|t| re.is_match(t)).unwrap_or(false)
}

#[cfg(test)]
mod tests {
  use super::*;
  use bytes::Bytes;
  use http::{HeaderMap, Method, Version};
  use std::net::{IpAddr, Ipv4Addr};

  fn make_ctx(uri: &str, method: Method, ip: IpAddr) -> RequestContext {
    RequestContext::new(
      ip,
      method,
      uri.parse().unwrap(),
      Version::HTTP_11,
      HeaderMap::new(),
      Bytes::new(),
    )
  }

  #[test]
  fn path_prefix_matches() {
    let ctx = make_ctx(
      "http://example.com/admin/users",
      Method::GET,
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    );

    let cond = Condition::PathPrefix {
      value: "/admin".to_string(),
    };
    assert!(cond.matches(&ctx));

    let cond = Condition::PathPrefix {
      value: "/api".to_string(),
    };
    assert!(!cond.matches(&ctx));
  }

  #[test]
  fn path_exact_strips_query() {
    let ctx = make_ctx(
      "http://example.com/api/test?foo=bar",
      Method::GET,
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    );

    let cond = Condition::PathExact {
      value: "/api/test".to_string(),
    };
    assert!(cond.matches(&ctx));

    let cond = Condition::PathExact {
      value: "/api/test?foo=bar".to_string(),
    };
    assert!(!cond.matches(&ctx));
  }

  #[test]
  fn method_is_case_insensitive() {
    let ctx = make_ctx(
      "http://example.com/",
      Method::POST,
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    );

    let cond = Condition::MethodIs {
      methods: vec![Method::POST, Method::PUT],
    };
    assert!(cond.matches(&ctx));

    let cond = Condition::MethodIs {
      methods: vec![Method::GET],
    };
    assert!(!cond.matches(&ctx));
  }

  #[test]
  fn header_contains_case_insensitive() {
    let mut headers = HeaderMap::new();
    headers.insert("user-agent", "Mozilla/5.0 Chrome".parse().unwrap());

    let ctx = RequestContext::new(
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
      Method::GET,
      "http://example.com/".parse().unwrap(),
      Version::HTTP_11,
      headers,
      Bytes::new(),
    );

    let cond = Condition::HeaderContains {
      header: "user-agent".to_string(),
      value: "chrome".to_string(),
    };
    assert!(cond.matches(&ctx));

    let cond = Condition::HeaderContains {
      header: "user-agent".to_string(),
      value: "firefox".to_string(),
    };
    assert!(!cond.matches(&ctx));
  }

  #[test]
  fn ipv4_cidr_matching() {
    let ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));

    // Should match
    assert!(ParsedCidr::parse("192.168.1.0/24").unwrap().contains(&ip));
    assert!(ParsedCidr::parse("192.168.0.0/16").unwrap().contains(&ip));
    assert!(ParsedCidr::parse("0.0.0.0/0").unwrap().contains(&ip));

    // Should not match
    assert!(!ParsedCidr::parse("10.0.0.0/8").unwrap().contains(&ip));
    assert!(!ParsedCidr::parse("192.168.2.0/24").unwrap().contains(&ip));
  }

  #[test]
  fn ipv6_cidr_matching() {
    let ip = IpAddr::V6("2001:db8::1".parse().unwrap());

    // Should match
    assert!(ParsedCidr::parse("2001:db8::/32").unwrap().contains(&ip));
    assert!(ParsedCidr::parse("2001::/16").unwrap().contains(&ip));
    assert!(ParsedCidr::parse("::/0").unwrap().contains(&ip));

    // Should not match
    assert!(!ParsedCidr::parse("2001:db9::/32").unwrap().contains(&ip));
    assert!(!ParsedCidr::parse("fe80::/10").unwrap().contains(&ip));
  }

  #[test]
  fn ip_in_range_condition() {
    let ctx = make_ctx(
      "http://example.com/",
      Method::GET,
      IpAddr::V4(Ipv4Addr::new(10, 0, 5, 100)),
    );

    let cond = Condition::IpInRange {
      cidrs: vec![
        ParsedCidr::parse("10.0.0.0/8").unwrap(),
        ParsedCidr::parse("192.168.0.0/16").unwrap(),
      ],
    };
    assert!(cond.matches(&ctx));

    let cond = Condition::IpInRange {
      cidrs: vec![ParsedCidr::parse("172.16.0.0/12").unwrap()],
    };
    assert!(!cond.matches(&ctx));
  }

  #[test]
  fn risk_above_threshold() {
    let mut ctx = make_ctx(
      "http://example.com/",
      Method::GET,
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    );
    ctx.risk_score = 0.75;

    let cond = Condition::RiskAbove { threshold: 0.5 };
    assert!(cond.matches(&ctx));

    let cond = Condition::RiskAbove { threshold: 0.8 };
    assert!(!cond.matches(&ctx));

    // Boundary test: when risk_score equals threshold, should NOT match (strict >)
    let cond = Condition::RiskAbove { threshold: 0.75 };
    assert!(!cond.matches(&ctx));
  }

  #[test]
  fn has_tag_condition() {
    let mut ctx = make_ctx(
      "http://example.com/",
      Method::GET,
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    );
    ctx.threat_tags.insert("sqli".to_string());
    ctx.threat_tags.insert("xss".to_string());

    let cond = Condition::HasTag {
      tag: "sqli".to_string(),
    };
    assert!(cond.matches(&ctx));

    let cond = Condition::HasTag {
      tag: "rce".to_string(),
    };
    assert!(!cond.matches(&ctx));
  }

  #[test]
  fn logical_and_condition() {
    let ctx = make_ctx(
      "http://example.com/admin",
      Method::POST,
      IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
    );

    let cond = Condition::And {
      conditions: vec![
        Condition::PathPrefix {
          value: "/admin".to_string(),
        },
        Condition::MethodIs {
          methods: vec![Method::POST],
        },
      ],
    };
    assert!(cond.matches(&ctx));

    let cond = Condition::And {
      conditions: vec![
        Condition::PathPrefix {
          value: "/admin".to_string(),
        },
        Condition::MethodIs {
          methods: vec![Method::GET],
        },
      ],
    };
    assert!(!cond.matches(&ctx));
  }

  #[test]
  fn logical_or_condition() {
    let ctx = make_ctx(
      "http://example.com/test",
      Method::GET,
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    );

    let cond = Condition::Or {
      conditions: vec![
        Condition::PathPrefix {
          value: "/admin".to_string(),
        },
        Condition::PathPrefix {
          value: "/test".to_string(),
        },
      ],
    };
    assert!(cond.matches(&ctx));

    let cond = Condition::Or {
      conditions: vec![
        Condition::PathPrefix {
          value: "/admin".to_string(),
        },
        Condition::PathPrefix {
          value: "/api".to_string(),
        },
      ],
    };
    assert!(!cond.matches(&ctx));
  }

  #[test]
  fn logical_not_condition() {
    let ctx = make_ctx(
      "http://example.com/public",
      Method::GET,
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    );

    let cond = Condition::Not {
      condition: Box::new(Condition::PathPrefix {
        value: "/admin".to_string(),
      }),
    };
    assert!(cond.matches(&ctx));

    let cond = Condition::Not {
      condition: Box::new(Condition::PathPrefix {
        value: "/public".to_string(),
      }),
    };
    assert!(!cond.matches(&ctx));
  }

  #[test]
  fn regex_match_uri() {
    let ctx = make_ctx(
      "http://example.com/api/v1/users/123",
      Method::GET,
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
    );

    let cond = Condition::RegexMatch {
      target: "uri".to_string(),
      pattern: r"/users/\d+".to_string(),
    };
    assert!(cond.matches(&ctx));

    let cond = Condition::RegexMatch {
      target: "uri".to_string(),
      pattern: r"/admin".to_string(),
    };
    assert!(!cond.matches(&ctx));
  }

  #[test]
  fn regex_match_body() {
    let ctx = RequestContext::new(
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
      Method::POST,
      "http://example.com/".parse().unwrap(),
      Version::HTTP_11,
      HeaderMap::new(),
      Bytes::from("username=admin&password=secret"),
    );

    let cond = Condition::RegexMatch {
      target: "body".to_string(),
      pattern: r"password=\w+".to_string(),
    };
    assert!(cond.matches(&ctx));
  }

  #[test]
  fn regex_match_header() {
    let mut headers = HeaderMap::new();
    headers.insert("authorization", "Bearer token123".parse().unwrap());

    let ctx = RequestContext::new(
      IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
      Method::GET,
      "http://example.com/".parse().unwrap(),
      Version::HTTP_11,
      headers,
      Bytes::new(),
    );

    let cond = Condition::RegexMatch {
      target: "header:authorization".to_string(),
      pattern: r"Bearer \w+".to_string(),
    };
    assert!(cond.matches(&ctx));
  }

  #[test]
  fn nested_logical_conditions() {
    let mut ctx = make_ctx(
      "http://example.com/admin",
      Method::POST,
      IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
    );

    // (PathPrefix AND MethodIs) OR RiskAbove
    let cond = Condition::Or {
      conditions: vec![
        Condition::And {
          conditions: vec![
            Condition::PathPrefix {
              value: "/admin".to_string(),
            },
            Condition::MethodIs {
              methods: vec![Method::POST],
            },
          ],
        },
        Condition::RiskAbove { threshold: 0.9 },
      ],
    };
    assert!(cond.matches(&ctx));

    ctx.risk_score = 0.95;
    assert!(cond.matches(&ctx)); // Still matches through second branch
  }
}
