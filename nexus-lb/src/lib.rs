pub mod balancer;
pub mod health;
pub mod upstream;

pub use balancer::LoadBalancer;
pub use upstream::{Upstream, UpstreamStatus};

#[cfg(test)]
mod tests {
  use crate::balancer::LoadBalancer;
  use crate::upstream::{Upstream, UpstreamStatus};
  use nexus_config::schema::LbAlgorithm;
  use parking_lot::RwLock;
  use std::sync::atomic::AtomicUsize;

  fn upstream(addr: &str, weight: u32, status: UpstreamStatus) -> Upstream {
    Upstream {
      name: addr.to_string(),
      addr: addr.to_string(),
      weight,
      status,
      consecutive_failures: 0,
      consecutive_successes: 0,
      active_connections: AtomicUsize::new(0),
    }
  }

  fn make_lb(upstreams: Vec<Upstream>, algo: LbAlgorithm) -> LoadBalancer {
    LoadBalancer {
      upstreams: RwLock::new(upstreams),
      counter: AtomicUsize::new(0),
      algorithm: algo,
      unhealthy_threshold: 3,
      healthy_threshold: 2,
    }
  }

  #[test]
  fn round_robin_distributes_across_all_upstreams() {
    let lb = make_lb(
      vec![
        upstream("a:80", 1, UpstreamStatus::Healthy),
        upstream("b:80", 1, UpstreamStatus::Healthy),
        upstream("c:80", 1, UpstreamStatus::Healthy),
      ],
      LbAlgorithm::RoundRobin,
    );
    let results: Vec<_> = (0..6).map(|_| lb.select().unwrap()).collect();
    assert!(results.contains(&"a:80".to_string()));
    assert!(results.contains(&"b:80".to_string()));
    assert!(results.contains(&"c:80".to_string()));
  }

  #[test]
  fn weighted_round_robin_favors_higher_weight() {
    let lb = make_lb(
      vec![
        upstream("a:80", 3, UpstreamStatus::Healthy),
        upstream("b:80", 1, UpstreamStatus::Healthy),
      ],
      LbAlgorithm::WeightedRoundRobin,
    );
    let results: Vec<String> = (0..8).map(|_| lb.select().unwrap()).collect();
    let a_count = results.iter().filter(|r| r.as_str() == "a:80").count();
    let b_count = results.iter().filter(|r| r.as_str() == "b:80").count();
    assert!(a_count > b_count);
  }

  #[test]
  fn weighted_round_robin_falls_back_when_all_weights_zero() {
    let lb = make_lb(
      vec![
        upstream("a:80", 0, UpstreamStatus::Healthy),
        upstream("b:80", 0, UpstreamStatus::Healthy),
      ],
      LbAlgorithm::WeightedRoundRobin,
    );
    // Should not panic, should return one of the upstreams
    let result = lb.select();
    assert!(result.is_ok());
  }

  #[test]
  fn least_connections_prefers_upstream_with_fewer_active_connections() {
    let a = upstream("a:80", 1, UpstreamStatus::Healthy);
    let b = upstream("b:80", 1, UpstreamStatus::Healthy);

    // Simulate existing load on a:80 so b:80 should be selected first.
    a.active_connections
      .store(5, std::sync::atomic::Ordering::Relaxed);

    let lb = make_lb(vec![a, b], LbAlgorithm::LeastConnections);

    let first = lb.select().unwrap();
    assert_eq!(first, "b:80");

    // After selecting b once, its active count should be 1.
    let selected_b_count = lb
      .upstreams
      .read()
      .iter()
      .find(|u| u.addr == "b:80")
      .map(|u| {
        u.active_connections
          .load(std::sync::atomic::Ordering::Relaxed)
      })
      .unwrap();
    assert_eq!(selected_b_count, 1);
  }

  #[test]
  fn unhealthy_upstream_is_excluded_from_selection() {
    let lb = make_lb(
      vec![
        upstream("a:80", 1, UpstreamStatus::Healthy),
        upstream("b:80", 1, UpstreamStatus::Unhealthy),
      ],
      LbAlgorithm::RoundRobin,
    );
    for _ in 0..10 {
      assert_eq!(lb.select().unwrap(), "a:80");
    }
  }

  #[test]
  fn failure_threshold_marks_upstream_unhealthy() {
    let lb = make_lb(
      vec![upstream("a:80", 1, UpstreamStatus::Healthy)],
      LbAlgorithm::RoundRobin,
    );
    lb.record_failure("a:80");
    lb.record_failure("a:80");
    assert_ne!(lb.statuses()[0].1, UpstreamStatus::Unhealthy);
    lb.record_failure("a:80");
    assert_eq!(lb.statuses()[0].1, UpstreamStatus::Unhealthy);
  }

  #[test]
  fn success_threshold_recovers_unhealthy_upstream() {
    let lb = make_lb(
      vec![upstream("a:80", 1, UpstreamStatus::Healthy)],
      LbAlgorithm::RoundRobin,
    );
    for _ in 0..3 {
      lb.record_failure("a:80");
    }
    lb.record_success("a:80");
    assert_eq!(lb.statuses()[0].1, UpstreamStatus::Unhealthy);
    lb.record_success("a:80");
    assert_eq!(lb.statuses()[0].1, UpstreamStatus::Healthy);
  }

  #[test]
  fn unknown_upstream_transitions_to_healthy_after_successes() {
    let lb = make_lb(
      vec![upstream("a:80", 1, UpstreamStatus::Unknown)],
      LbAlgorithm::RoundRobin,
    );
    lb.record_success("a:80");
    assert_eq!(lb.statuses()[0].1, UpstreamStatus::Unknown);
    lb.record_success("a:80");
    assert_eq!(lb.statuses()[0].1, UpstreamStatus::Healthy);
  }

  #[test]
  fn single_unhealthy_upstream_returns_error() {
    let lb = make_lb(
      vec![upstream("a:80", 1, UpstreamStatus::Unhealthy)],
      LbAlgorithm::RoundRobin,
    );
    let result = lb.select();
    assert!(result.is_err());
    assert!(matches!(
      result.unwrap_err(),
      nexus_common::NexusError::NoHealthyUpstream
    ));
  }
}
