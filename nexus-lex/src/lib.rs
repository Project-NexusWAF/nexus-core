//! nexus-lex — Regex-based lexical threat detection for NexusWAF
//!
//! ## Design
//!
//! Precompiles all regex patterns at startup (via `once_cell::sync::Lazy`).
//! Pattern matching runs entirely in memory, no I/O.
//!
//! ## Pattern categories
//! - SQL Injection (SQLi)
//! - Cross-Site Scripting (XSS)
//! - Path Traversal
//! - Command Injection
//!
//! ## Performance
//! - Regex sets compiled once, reused for every request.
//! - `regex::RegexSet` matches N patterns in a single pass.
//! - Sub-millisecond for typical payloads.

pub mod layer;
pub mod patterns;
pub mod scanner;

pub use layer::LexicalLayer;
pub use scanner::{LexicalScanner, ScanResult, ThreatMatch};
