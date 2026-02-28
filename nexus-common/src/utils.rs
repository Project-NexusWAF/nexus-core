use std::time::{Duration, Instant};
pub fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
  if s.len() <= max_bytes {
    return s;
  }
  let mut end = max_bytes;
  while !s.is_char_boundary(end) {
    end -= 1;
  }
  &s[..end]
}
pub fn format_duration(d: Duration) -> String {
  let us = d.as_micros();
  if us < 1_000 {
    format!("{}µs", us)
  } else if us < 1_000_000 {
    format!("{:.2}ms", us as f64 / 1_000.0)
  } else {
    format!("{:.2}s", us as f64 / 1_000_000.0)
  }
}

pub struct ScopedTimer {
  label: &'static str,
  start: Instant,
}

impl ScopedTimer {
  pub fn new(label: &'static str) -> Self {
    Self {
      label,
      start: Instant::now(),
    }
  }

  pub fn elapsed_us(&self) -> u64 {
    self.start.elapsed().as_micros() as u64
  }
}

impl Drop for ScopedTimer {
  fn drop(&mut self) {
    tracing::debug!(
      label = self.label,
      elapsed = format_duration(self.start.elapsed()).as_str(),
      "layer timing"
    );
  }
}

pub fn sanitise_for_log(s: &str, max_len: usize) -> String {
  let s = truncate_utf8(s, max_len);
  s.chars()
    .map(|c| if c.is_control() { '?' } else { c })
    .collect()
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn truncate_ascii() {
    assert_eq!(truncate_utf8("hello world", 5), "hello");
  }

  #[test]
  fn truncate_at_char_boundary() {
    let s = "éllo";
    let t = truncate_utf8(s, 1);
    assert!(t.is_empty());
  }

  #[test]
  fn format_us() {
    assert_eq!(format_duration(Duration::from_micros(500)), "500µs");
  }

  #[test]
  fn format_ms() {
    assert_eq!(format_duration(Duration::from_millis(250)), "250.00ms");
  }
}
