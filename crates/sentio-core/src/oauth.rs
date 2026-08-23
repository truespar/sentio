use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// OAuthClientStatus  (CHECK: active, revoked)
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
pub enum OAuthClientStatus {
    Active,
    Revoked,
}

// ──────────────────────────────────────────────────────────────────────────────
// CodeChallengeMethod  (CHECK: S256, plain)
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
pub enum CodeChallengeMethod {
    #[strum(serialize = "S256")]
    #[serde(rename = "S256")]
    S256,
    #[strum(serialize = "plain")]
    #[serde(rename = "plain")]
    Plain,
}

// ──────────────────────────────────────────────────────────────────────────────
// OAuthTokenType  (CHECK: access, refresh)
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
pub enum OAuthTokenType {
    Access,
    Refresh,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn oauth_client_status_display() {
        assert_eq!(OAuthClientStatus::Active.to_string(), "active");
        assert_eq!(OAuthClientStatus::Revoked.to_string(), "revoked");
    }

    #[test]
    fn code_challenge_method_display() {
        assert_eq!(CodeChallengeMethod::S256.to_string(), "S256");
        assert_eq!(CodeChallengeMethod::Plain.to_string(), "plain");
    }

    #[test]
    fn code_challenge_method_from_str() {
        assert_eq!(
            "S256".parse::<CodeChallengeMethod>().unwrap(),
            CodeChallengeMethod::S256
        );
        assert_eq!(
            "plain".parse::<CodeChallengeMethod>().unwrap(),
            CodeChallengeMethod::Plain
        );
        assert!("s256".parse::<CodeChallengeMethod>().is_err());
    }

    #[test]
    fn oauth_token_type_display() {
        assert_eq!(OAuthTokenType::Access.to_string(), "access");
        assert_eq!(OAuthTokenType::Refresh.to_string(), "refresh");
    }
}
