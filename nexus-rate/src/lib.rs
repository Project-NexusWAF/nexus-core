//! nexus-rate — Token-bucket rate limiter for NexusWAF
//!
//! ## Design
//!
//! Uses a **token bucket** algorithm per IP address:
//! - Each IP gets a bucket of `burst_capacity` tokens.
//! - Tokens refill at `requests_per_second` tokens/sec continuously.
//! - Each request consumes 1 token.
//! - If the bucket is empty → rate limited.
//!
//! Implementation details:
//! - `DashMap<IpAddr, Bucket>` — sharded concurrent hashmap, no global lock.
//! - Each bucket has its own `parking_lot::Mutex` — lock contention only
//!   for the same IP, never cross-IP.
//! - Lazy refill: we don't run a timer per bucket. Instead we calculate
//!   how many tokens have accumulated since the last request on demand.
//! - Background cleanup task evicts idle buckets every `cleanup_interval`.

pub mod bucket;
pub mod layer;
pub mod limiter;
pub mod policy;

pub use layer::RateLayer;
pub use limiter::RateLimiter;
pub use policy::RatePolicy;
