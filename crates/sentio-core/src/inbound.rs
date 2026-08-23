use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// InboundRouteMatchType  (CHECK: exact, regex, domain, catch_all)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    Serialize,
    Deserialize,
    strum::Display,
    strum::EnumString,
    utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
#[strum(serialize_all = "snake_case")]
pub enum InboundRouteMatchType {
    Exact,
    Regex,
    Domain,
    CatchAll,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inbound_route_match_type_display() {
        assert_eq!(InboundRouteMatchType::Exact.to_string(), "exact");
        assert_eq!(InboundRouteMatchType::Regex.to_string(), "regex");
        assert_eq!(InboundRouteMatchType::Domain.to_string(), "domain");
        assert_eq!(InboundRouteMatchType::CatchAll.to_string(), "catch_all");
    }

    #[test]
    fn inbound_route_match_type_from_str() {
        assert_eq!(
            "catch_all".parse::<InboundRouteMatchType>().unwrap(),
            InboundRouteMatchType::CatchAll
        );
        assert_eq!(
            "exact".parse::<InboundRouteMatchType>().unwrap(),
            InboundRouteMatchType::Exact
        );
        assert!("invalid".parse::<InboundRouteMatchType>().is_err());
    }
}
