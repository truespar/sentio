use serde::{Deserialize, Serialize};

/// Liveness probe status.
///
/// Reports whether the process is alive and can respond at all.
/// A `Dead` status should trigger a container restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiveStatus {
    Alive,
    Dead,
}

impl LiveStatus {
    pub fn is_alive(self) -> bool {
        self == Self::Alive
    }

    pub fn http_status_code(self) -> u16 {
        match self {
            Self::Alive => 200,
            Self::Dead => 503,
        }
    }
}

/// Readiness probe status.
///
/// Reports whether the service is ready to accept traffic.
/// A `NotReady` status should remove the instance from the load balancer
/// but NOT trigger a restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReadyStatus {
    Ready,
    NotReady,
}

impl ReadyStatus {
    pub fn is_ready(self) -> bool {
        self == Self::Ready
    }

    pub fn http_status_code(self) -> u16 {
        match self {
            Self::Ready => 200,
            Self::NotReady => 503,
        }
    }
}

/// Aggregated health check response returned by the `/healthz` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthReport {
    pub live: LiveStatus,
    pub ready: ReadyStatus,
    #[serde(default)]
    pub checks: Vec<ComponentCheck>,
}

impl HealthReport {
    pub fn healthy() -> Self {
        Self {
            live: LiveStatus::Alive,
            ready: ReadyStatus::Ready,
            checks: Vec::new(),
        }
    }

    pub fn http_status_code(&self) -> u16 {
        if self.live.is_alive() && self.ready.is_ready() {
            200
        } else {
            503
        }
    }
}

/// Status of an individual subsystem (e.g. database, KV store, queue).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentCheck {
    pub name: String,
    pub status: ComponentStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ComponentStatus {
    Ok,
    Degraded,
    Down,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_status_codes() {
        assert_eq!(LiveStatus::Alive.http_status_code(), 200);
        assert_eq!(LiveStatus::Dead.http_status_code(), 503);
        assert!(LiveStatus::Alive.is_alive());
        assert!(!LiveStatus::Dead.is_alive());
    }

    #[test]
    fn ready_status_codes() {
        assert_eq!(ReadyStatus::Ready.http_status_code(), 200);
        assert_eq!(ReadyStatus::NotReady.http_status_code(), 503);
        assert!(ReadyStatus::Ready.is_ready());
        assert!(!ReadyStatus::NotReady.is_ready());
    }

    #[test]
    fn healthy_report() {
        let report = HealthReport::healthy();
        assert_eq!(report.http_status_code(), 200);
        assert!(report.checks.is_empty());
    }

    #[test]
    fn unhealthy_report_returns_503() {
        let report = HealthReport {
            live: LiveStatus::Alive,
            ready: ReadyStatus::NotReady,
            checks: vec![ComponentCheck {
                name: "database".to_string(),
                status: ComponentStatus::Down,
                message: Some("connection refused".to_string()),
            }],
        };
        assert_eq!(report.http_status_code(), 503);
    }

    #[test]
    fn health_report_json_roundtrip() {
        let report = HealthReport {
            live: LiveStatus::Alive,
            ready: ReadyStatus::Ready,
            checks: vec![
                ComponentCheck {
                    name: "database".to_string(),
                    status: ComponentStatus::Ok,
                    message: None,
                },
                ComponentCheck {
                    name: "redis".to_string(),
                    status: ComponentStatus::Degraded,
                    message: Some("high latency".to_string()),
                },
            ],
        };
        let json = serde_json::to_string(&report).unwrap();
        let parsed: HealthReport = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.live, LiveStatus::Alive);
        assert_eq!(parsed.ready, ReadyStatus::Ready);
        assert_eq!(parsed.checks.len(), 2);
        assert_eq!(parsed.checks[0].status, ComponentStatus::Ok);
        assert!(parsed.checks[0].message.is_none());
        assert_eq!(parsed.checks[1].status, ComponentStatus::Degraded);
    }

    #[test]
    fn live_status_serde() {
        let json = serde_json::to_string(&LiveStatus::Alive).unwrap();
        assert_eq!(json, "\"alive\"");
        let json = serde_json::to_string(&LiveStatus::Dead).unwrap();
        assert_eq!(json, "\"dead\"");
    }

    #[test]
    fn ready_status_serde() {
        let json = serde_json::to_string(&ReadyStatus::Ready).unwrap();
        assert_eq!(json, "\"ready\"");
        let json = serde_json::to_string(&ReadyStatus::NotReady).unwrap();
        assert_eq!(json, "\"not_ready\"");
    }
}
