use async_trait::async_trait;

use crate::{Decision, RequestContext, Result};

/// The core abstraction for every security layer in the pipeline.
///
/// Each layer receives a mutable `RequestContext`, annotates it with
/// findings (threat tags, risk score, etc.), and returns a `Decision`.
///
/// Layers are async and can do I/O (e.g. ML inference gRPC call),
/// but the fast layers (rate, lexical) should be pure CPU.
///
/// # Short-circuit contract
/// If a layer returns `Decision::Block` or `Decision::RateLimit`,
/// the pipeline stops and does not call subsequent layers.
#[async_trait]
pub trait InnerLayer: Send + Sync {
  /// The human-readable name of this layer (used in logs and metrics).
  fn name(&self) -> &'static str;

  /// Analyse the request and return a decision.
  ///
  /// The layer MUST:
  /// - Not panic on malformed input.
  /// - Return `Ok(Decision::Allow)` if it has no findings.
  /// - Annotate `ctx` with threat tags / risk score before returning Block.
  async fn analyse(&self, ctx: &mut RequestContext) -> Result<Decision>;

  /// Called once on startup to allow the layer to warm up
  /// (e.g. compile regexes, connect to ML service).
  /// Default: no-op.
  async fn init(&self) -> Result<()> {
    Ok(())
  }

  /// Called when the layer's configuration is hot-reloaded.
  /// Default: no-op (layers that don't support hot-reload ignore this).
  async fn reload(&self) -> Result<()> {
    Ok(())
  }

  /// Priority of this layer in the pipeline.
  /// Lower number = runs earlier. Standard order:
  ///   Rate(0), Lexical(10), Grammar(20), Rules(30), ML(40)
  fn priority(&self) -> u8;
}

/// A boxed, heap-allocated layer — used for storing heterogeneous layers
/// in a `Vec<Box<dyn Layer>>`.
pub type Layer = Box<dyn InnerLayer>;
