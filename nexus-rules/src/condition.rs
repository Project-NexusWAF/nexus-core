use nexus_common::RequestContext;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

/// A condition that can be evaluated against a request
#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Condition {
    /// Match if URI starts with the given prefix
    PathPrefix { value: String },

    /// Match if path (without query string) equals the given value
    PathExact { value: String },

    /// Match if HTTP method is in the list
    MethodIs { methods: Vec<String> },

    /// Match if a header contains a specific value (case-insensitive)
    HeaderContains { header: String, value: String },

    /// Match if client IP is in any of the CIDR ranges
    IpInRange { cidrs: Vec<String> },

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
            Self::PathPrefix { value } => ctx.uri.starts_with(value),

            Self::PathExact { value } => {
                // Extract path without query string
                let path = ctx.uri.split('?').next().unwrap_or(&ctx.uri);
                path == value
            }

            Self::MethodIs { methods } => {
                let method_str = ctx.method.0.as_str();
                methods.iter().any(|m| m.eq_ignore_ascii_case(method_str))
            }

            Self::HeaderContains { header, value } => {
                if let Some(header_value) = ctx.headers.0.get(header) {
                    if let Ok(header_str) = header_value.to_str() {
                        return header_str
                            .to_lowercase()
                            .contains(&value.to_lowercase());
                    }
                }
                false
            }

            Self::IpInRange { cidrs } => {
                cidrs.iter().any(|cidr| ip_in_cidr(&ctx.client_ip, cidr))
            }

            Self::RiskAbove { threshold } => ctx.risk_score > *threshold,

            Self::HasTag { tag } => ctx.threat_tags.contains(tag),

            Self::And { conditions } => conditions.iter().all(|c| c.matches(ctx)),

            Self::Or { conditions } => conditions.iter().any(|c| c.matches(ctx)),

            Self::Not { condition } => !condition.matches(ctx),

            Self::RegexMatch { target, pattern } => match_regex(ctx, target, pattern),
        }
    }
}

/// Check if an IP address falls within a CIDR range
fn ip_in_cidr(ip: &IpAddr, cidr: &str) -> bool {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return false;
    }

    let network_str = parts[0];
    let prefix_len = parts[1].parse::<u8>().ok();

    if prefix_len.is_none() {
        return false;
    }
    let prefix_len = prefix_len.unwrap();

    // Parse network address
    let network_addr: IpAddr = match network_str.parse() {
        Ok(addr) => addr,
        Err(_) => return false,
    };

    // Must be same IP version
    match (ip, network_addr) {
        (IpAddr::V4(ip4), IpAddr::V4(net4)) => {
            if prefix_len > 32 {
                return false;
            }
            ipv4_in_range(*ip4, net4, prefix_len)
        }
        (IpAddr::V6(ip6), IpAddr::V6(net6)) => {
            if prefix_len > 128 {
                return false;
            }
            ipv6_in_range(*ip6, net6, prefix_len)
        }
        _ => false, // Mixed IP versions
    }
}

fn ipv4_in_range(ip: Ipv4Addr, network: Ipv4Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true; // 0.0.0.0/0 matches everything
    }

    let ip_bits = u32::from(ip);
    let net_bits = u32::from(network);
    let mask = !0u32 << (32 - prefix_len);

    (ip_bits & mask) == (net_bits & mask)
}

fn ipv6_in_range(ip: Ipv6Addr, network: Ipv6Addr, prefix_len: u8) -> bool {
    if prefix_len == 0 {
        return true; // ::/0 matches everything
    }

    let ip_bits = u128::from(ip);
    let net_bits = u128::from(network);
    let mask = !0u128 << (128 - prefix_len);

    (ip_bits & mask) == (net_bits & mask)
}

/// Match a regex pattern against a target field
fn match_regex(ctx: &RequestContext, target: &str, pattern: &str) -> bool {
    // Cache compiled regex per pattern
    thread_local! {
        static REGEX_CACHE: std::cell::RefCell<std::collections::HashMap<String, Regex>> = 
            std::cell::RefCell::new(std::collections::HashMap::new());
    }

    let re = REGEX_CACHE.with(|cache| {
        let mut cache = cache.borrow_mut();
        cache
            .entry(pattern.to_string())
            .or_insert_with(|| Regex::new(pattern).ok())
            .clone()
    });

    let re = match re {
        Some(r) => r,
        None => return false, // Invalid regex
    };

    let text = match target {
        "uri" => Some(ctx.uri.as_str()),
        "body" => std::str::from_utf8(&ctx.body).ok(),
        s if s.starts_with("header:") => {
            let header_name = &s[7..];
            ctx.headers
                .0
                .get(header_name)
                .and_then(|v| v.to_str().ok())
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
    use std::net::{Ipv4Addr, Ipv6Addr};

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
            methods: vec!["post".to_string(), "PUT".to_string()],
        };
        assert!(cond.matches(&ctx));

        let cond = Condition::MethodIs {
            methods: vec!["GET".to_string()],
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
        assert!(ip_in_cidr(&ip, "192.168.1.0/24"));
        assert!(ip_in_cidr(&ip, "192.168.0.0/16"));
        assert!(ip_in_cidr(&ip, "0.0.0.0/0"));

        // Should not match
        assert!(!ip_in_cidr(&ip, "10.0.0.0/8"));
        assert!(!ip_in_cidr(&ip, "192.168.2.0/24"));
    }

    #[test]
    fn ipv6_cidr_matching() {
        let ip = IpAddr::V6("2001:db8::1".parse().unwrap());

        // Should match
        assert!(ip_in_cidr(&ip, "2001:db8::/32"));
        assert!(ip_in_cidr(&ip, "2001::/16"));
        assert!(ip_in_cidr(&ip, "::/0"));

        // Should not match
        assert!(!ip_in_cidr(&ip, "2001:db9::/32"));
        assert!(!ip_in_cidr(&ip, "fe80::/10"));
    }

    #[test]
    fn ip_in_range_condition() {
        let ctx = make_ctx(
            "http://example.com/",
            Method::GET,
            IpAddr::V4(Ipv4Addr::new(10, 0, 5, 100)),
        );

        let cond = Condition::IpInRange {
            cidrs: vec!["10.0.0.0/8".to_string(), "192.168.0.0/16".to_string()],
        };
        assert!(cond.matches(&ctx));

        let cond = Condition::IpInRange {
            cidrs: vec!["172.16.0.0/12".to_string()],
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
    }

    #[test]
    fn has_tag_condition() {
        let mut ctx = make_ctx(
            "http://example.com/",
            Method::GET,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
        );
        ctx.threat_tags.push("sqli".to_string());
        ctx.threat_tags.push("xss".to_string());

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
        let mut ctx = make_ctx(
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
                    methods: vec!["POST".to_string()],
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
                    methods: vec!["GET".to_string()],
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
                            methods: vec!["POST".to_string()],
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
