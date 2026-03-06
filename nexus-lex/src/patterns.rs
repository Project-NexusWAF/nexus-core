//! Lexical threat detection patterns.
//!
//! All patterns are compiled once at process start via `once_cell::sync::Lazy`.
//! We use `regex::RegexSet` where multiple patterns are checked together,
//! enabling the regex engine to scan the string once for all patterns.
//!
//! Pattern design philosophy:
//! - Each pattern targets a distinct attack primitive.
//! - Favour precision over recall — false positives are expensive in a WAF.
//! - Patterns are case-insensitive where the attack is case-insensitive.
//! - URL-decoded input is assumed (done by `RequestContext` on construction).

use once_cell::sync::Lazy;
use regex::{Regex, RegexSet};

/// SQL injection patterns (case-insensitive).
///
/// Coverage:
/// - Classic tautology attacks: `' OR 1=1`, `' OR 'a'='a`
/// - UNION-based data extraction: `UNION SELECT`
/// - Comment-based termination: `--`, `#`, `/*`
/// - Stacked queries: `; DROP TABLE`, `; INSERT INTO`
/// - Blind injection timing: `SLEEP()`, `BENCHMARK()`, `WAITFOR DELAY`
/// - Boolean blind: `AND 1=1`, `AND 1=2`
/// - Error-based: `EXTRACTVALUE`, `UPDATEXML`
/// - Out-of-band: `INTO OUTFILE`, `LOAD_FILE`
pub static SQLI_SET: Lazy<RegexSet> = Lazy::new(|| {
  RegexSet::new([
    // Tautology: quote followed by OR condition
    r"(?i)'\s*(or|and)\s+['`]?\w*['`]?\s*=\s*['`]?\w*['`]?",
    // Tautology: numeric comparison
    r"(?i)'\s*(or|and)\s+\d+\s*=\s*\d+",
    // UNION-based extraction
    r"(?i)\bunion\b.{0,30}\bselect\b",
    // SQL comment terminators after a quote
    r"(?i)'[^']*(-{2}|#|/\*)",
    // Stacked query terminators
    r"(?i);\s*(drop|delete|insert|update|create|alter|truncate|exec|execute)\b",
    // Time-based blind
    r"(?i)\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(",
    // Boolean blind
    r"(?i)\band\s+\d+\s*[=<>]\s*\d+",
    // Error-based extraction
    r"(?i)\b(extractvalue|updatexml|exp|floor\(rand)\s*\(",
    // File I/O
    r"(?i)\b(into\s+outfile|load_file)\b",
    // Subquery injection
    r"(?i)\bselect\b.{0,50}\bfrom\b.{0,50}\bwhere\b",
    // xp_cmdshell (MSSQL RCE)
    r"(?i)\bxp_cmdshell\b",
    // System table probing
    r"(?i)\b(information_schema|sys\.tables|pg_catalog|all_tables)\b",
  ])
  .expect("SQLI patterns must compile")
});

/// High-confidence single-match SQLi patterns (for detailed reporting).
pub static SQLI_NAMED: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
  vec![
    (
      "sqli_tautology",
      Regex::new(r"(?i)'\s*(or|and)\s+['`]?\w*['`]?\s*=\s*['`]?\w*['`]?").unwrap(),
    ),
    (
      "sqli_union_select",
      Regex::new(r"(?i)\bunion\b.{0,30}\bselect\b").unwrap(),
    ),
    (
      "sqli_stacked_query",
      Regex::new(r"(?i);\s*(drop|delete|insert|update|create|alter|truncate)\b").unwrap(),
    ),
    (
      "sqli_time_blind",
      Regex::new(r"(?i)\b(sleep|benchmark|waitfor\s+delay|pg_sleep)\s*\(").unwrap(),
    ),
    (
      "sqli_xp_cmdshell",
      Regex::new(r"(?i)\bxp_cmdshell\b").unwrap(),
    ),
  ]
});

/// XSS patterns (case-insensitive).
///
/// Coverage:
/// - Script tag injection: `<script>`, `</script>`
/// - Event handler injection: `onerror=`, `onload=`, `onclick=`, etc.
/// - Javascript URI: `javascript:`
/// - Data URI: `data:text/html`
/// - Template injection: `{{`, `}}`  (covers Angular/Vue/Jinja)
/// - DOM clobbering: `<img src=x onerror=`
/// - SVG/MathML vectors
/// - CSS injection via `expression()`
pub static XSS_SET: Lazy<RegexSet> = Lazy::new(|| {
  RegexSet::new([
    // Script tag (with optional attributes and whitespace mangling)
    r"(?i)<\s*script\b",
    // Closing script tag
    r"(?i)<\s*/\s*script\s*>",
    // Event handlers (on* attributes)
    r#"(?i)\bon\w+\s*=\s*["']?[^"'\s>]"#,
    // javascript: URI
    r"(?i)javascript\s*:",
    // data: URI with HTML/script
    r"(?i)data\s*:\s*text/(html|javascript)",
    // Template injection
    r"\{\{.{0,100}\}\}",
    // iframe injection
    r"(?i)<\s*iframe\b",
    // SVG with onload
    r"(?i)<\s*svg\b.{0,50}\bon\w+\s*=",
    // CSS expression()
    r"(?i)expression\s*\(",
    // Encoded script variations: &#x3C;script or \u003cscript
    r"(?i)(&#x?[0-9a-f]+;|\\u[0-9a-f]{4}).{0,10}script",
    // base64-encoded payloads in src/href
    r#"(?i)(src|href)\s*=\s*["']?\s*data:"#,
    // document.write / eval
    r"(?i)\b(document\.write|eval|setTimeout|setInterval)\s*\(",
  ])
  .expect("XSS patterns must compile")
});

pub static XSS_NAMED: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
  vec![
    ("xss_script_tag", Regex::new(r"(?i)<\s*script\b").unwrap()),
    (
      "xss_event_handler",
      Regex::new(r#"(?i)\bon\w+\s*=\s*["']?[^"'\s>]"#).unwrap(),
    ),
    (
      "xss_javascript_uri",
      Regex::new(r"(?i)javascript\s*:").unwrap(),
    ),
    ("xss_template_inj", Regex::new(r"\{\{.{0,100}\}\}").unwrap()),
  ]
});

/// Path traversal patterns.
///
/// Coverage:
/// - Classic `../` and `..\`
/// - URL-encoded variants: `%2e%2e%2f`, `%2e%2e/`, `..%2f`
/// - Double-encoded: `%252e%252e`
/// - Null byte injection: `%00`
/// - Absolute path access: `/etc/passwd`, `/etc/shadow`, `/proc/`
/// - Windows paths: `C:\`, `\\server\share`
pub static PATH_TRAVERSAL_SET: Lazy<RegexSet> = Lazy::new(|| {
  RegexSet::new([
    // Classic traversal
    r"\.\./",
    r"\.\.\\",
    // URL-encoded
    r"(?i)(%2e%2e|%252e%252e)(%2f|%5c|/|\\)",
    r"(?i)\.\.((%2f|%5c))",
    // Null byte
    r"%00",
    // Sensitive Unix paths
    r"(?i)/etc/(passwd|shadow|hosts|crontab|sudoers|ssh/)",
    r"(?i)/proc/(self|[0-9]+)/(environ|cmdline|maps|mem)",
    r"(?i)/var/(log|www|run)/",
    r"(?i)/(home|root)/[^/]+/\.",
    // Windows paths
    r"(?i)(c:|d:)\\",
    r"(?i)\\\\[a-z0-9_]+\\",
    // Boot/system dirs
    r"(?i)/(boot|sys|dev|bin|sbin)/",
  ])
  .expect("Path traversal patterns must compile")
});

pub static PATH_TRAVERSAL_NAMED: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
  vec![
    ("traversal_dotdot", Regex::new(r"\.\./|\.\.\\").unwrap()),
    (
      "traversal_encoded",
      Regex::new(r"(?i)(%2e%2e|%252e%252e)(%2f|%5c|/|\\)").unwrap(),
    ),
    ("traversal_null_byte", Regex::new(r"%00").unwrap()),
    (
      "traversal_etc_passwd",
      Regex::new(r"(?i)/etc/passwd").unwrap(),
    ),
  ]
});

/// Command injection patterns.
///
/// Coverage:
/// - Shell metacharacters: `;`, `|`, `&&`, `||`, backtick
/// - Common dangerous commands: `cat`, `wget`, `curl`, `bash`, `sh`, `python`
/// - Redirection: `>`, `>>`, `<`
/// - Command substitution: `$(...)`, `` `...` ``
/// - Environment variable injection: `$IFS`, `$PATH`
/// - Encoded semicolons/pipes: `%3b`, `%7c`
pub static CMD_INJECTION_SET: Lazy<RegexSet> = Lazy::new(|| {
  RegexSet::new([
    // Shell operators after a value
    r"[;|`]\s*(ls|cat|echo|wget|curl|bash|sh|python|perl|ruby|php|nc|ncat|netcat)\b",
    // Subshell / command substitution
    r"\$\([^)]{1,100}\)",
    // Backtick command substitution
    r"`[^`]{1,100}`",
    // Encoded shell metacharacters
    r"(?i)(%3b|%7c|%26%26|%7c%7c)\s*\w+",
    // Dangerous standalone commands (unquoted, in param values)
    r"(?i)\b(wget|curl)\b.{0,50}(http|ftp)://",
    // /bin/sh, /bin/bash
    r"(?i)/bin/(sh|bash|dash|zsh|ksh|csh|tcsh)",
    // Pipe to shell
    r"(?i)\|\s*(bash|sh|python|perl|ruby)\b",
    // $IFS trick (space evasion)
    r"\$IFS",
    // Redirection with sensitive targets
    r"(?i)>\s*/etc/",
  ])
  .expect("Command injection patterns must compile")
});

pub static CMD_INJECTION_NAMED: Lazy<Vec<(&'static str, Regex)>> = Lazy::new(|| {
  vec![
    (
      "cmdi_shell_operator",
      Regex::new(r"[;|`]\s*(ls|cat|echo|wget|curl|bash|sh)\b").unwrap(),
    ),
    ("cmdi_subshell", Regex::new(r"\$\([^)]{1,100}\)").unwrap()),
    ("cmdi_backtick", Regex::new(r"`[^`]{1,100}`").unwrap()),
    (
      "cmdi_bin_shell",
      Regex::new(r"(?i)/bin/(sh|bash|dash)").unwrap(),
    ),
  ]
});

/// Common evasion technique patterns — applied after the main sets.
///
/// These detect attempts to bypass WAF by encoding or obfuscating payloads.
pub static EVASION_SET: Lazy<RegexSet> = Lazy::new(|| {
  RegexSet::new([
    // Excessive URL encoding (normal payloads shouldn't have many %XX)
    r"(%[0-9a-fA-F]{2}){5,}",
    // Unicode lookalike characters
    r"[\u0430-\u044F\u00E0-\u00FF].{0,10}(select|union|script)",
    // HTML entity encoding of angle brackets
    r"(?i)(&lt;|&gt;|&#\d+;).{0,20}(script|img|svg)",
    // Double URL encoding
    r"(?i)%25[0-9a-f]{2}",
    // Null byte in non-binary payload
    r"\x00",
  ])
  .expect("Evasion patterns must compile")
});
