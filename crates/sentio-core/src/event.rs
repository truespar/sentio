use serde::{Deserialize, Serialize};

// ──────────────────────────────────────────────────────────────────────────────
// EventType  (CHECK: queued, processed, delivered, deferred, bounced,
//                    dropped, held, released)
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
pub enum EventType {
    Queued,
    Processed,
    Delivered,
    Deferred,
    Bounced,
    Dropped,
    Held,
    Released,
}

// ──────────────────────────────────────────────────────────────────────────────
// EngagementEventType  (CHECK: opened, clicked, unsubscribed)
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
pub enum EngagementEventType {
    Opened,
    Clicked,
    Unsubscribed,
}

// ──────────────────────────────────────────────────────────────────────────────
// BounceClass  (CHECK: hard, soft, block)
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
pub enum BounceClass {
    Hard,
    Soft,
    Block,
}

// ──────────────────────────────────────────────────────────────────────────────
// DeviceType  (CHECK: desktop, mobile, tablet, unknown)
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
pub enum DeviceType {
    Desktop,
    Mobile,
    Tablet,
    Unknown,
}

// ──────────────────────────────────────────────────────────────────────────────
// MailboxStatus  (CHECK: active, disabled)
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
pub enum MailboxStatus {
    Active,
    Disabled,
}

// ──────────────────────────────────────────────────────────────────────────────
// ErrorSeverity  (CHECK: warning, error, critical)
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
pub enum ErrorSeverity {
    Warning,
    Error,
    Critical,
}

// ──────────────────────────────────────────────────────────────────────────────
// ErrorComponent  (CHECK: smtp_server, smtp_client, queue, api, webhooks,
//                         auth, abuse, storage, spam, llm)
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
pub enum ErrorComponent {
    SmtpServer,
    SmtpClient,
    Queue,
    Api,
    Webhooks,
    Auth,
    Abuse,
    Storage,
    Spam,
    Llm,
}

// ──────────────────────────────────────────────────────────────────────────────
// ErrorCategory  (CHECK: database, redis, queue, storage, smtp, auth,
//                        rate_limit, not_found, validation, internal, config)
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
pub enum ErrorCategory {
    Database,
    Redis,
    Queue,
    Storage,
    Smtp,
    Auth,
    RateLimit,
    NotFound,
    Validation,
    Internal,
    Config,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn event_type_display() {
        assert_eq!(EventType::Queued.to_string(), "queued");
        assert_eq!(EventType::Processed.to_string(), "processed");
        assert_eq!(EventType::Delivered.to_string(), "delivered");
        assert_eq!(EventType::Deferred.to_string(), "deferred");
        assert_eq!(EventType::Bounced.to_string(), "bounced");
        assert_eq!(EventType::Dropped.to_string(), "dropped");
        assert_eq!(EventType::Held.to_string(), "held");
        assert_eq!(EventType::Released.to_string(), "released");
    }

    #[test]
    fn event_type_from_str() {
        assert_eq!("queued".parse::<EventType>().unwrap(), EventType::Queued);
        assert_eq!(
            "released".parse::<EventType>().unwrap(),
            EventType::Released
        );
        assert!("invalid".parse::<EventType>().is_err());
    }

    #[test]
    fn event_type_serde_roundtrip() {
        let et = EventType::Bounced;
        let json = serde_json::to_string(&et).unwrap();
        assert_eq!(json, "\"bounced\"");
        let parsed: EventType = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, et);
    }

    #[test]
    fn engagement_event_type_display() {
        assert_eq!(EngagementEventType::Opened.to_string(), "opened");
        assert_eq!(EngagementEventType::Clicked.to_string(), "clicked");
        assert_eq!(
            EngagementEventType::Unsubscribed.to_string(),
            "unsubscribed"
        );
    }

    #[test]
    fn bounce_class_display() {
        assert_eq!(BounceClass::Hard.to_string(), "hard");
        assert_eq!(BounceClass::Soft.to_string(), "soft");
        assert_eq!(BounceClass::Block.to_string(), "block");
    }

    #[test]
    fn device_type_display() {
        assert_eq!(DeviceType::Desktop.to_string(), "desktop");
        assert_eq!(DeviceType::Mobile.to_string(), "mobile");
        assert_eq!(DeviceType::Tablet.to_string(), "tablet");
        assert_eq!(DeviceType::Unknown.to_string(), "unknown");
    }
}
