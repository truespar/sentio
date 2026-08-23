use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ──────────────────────────────────────────────────────────────────────────────
// MessageId  (UUIDv7 - time-ordered for partitioned tables)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
pub struct MessageId(pub Uuid);

impl MessageId {
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }
}

impl Default for MessageId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for MessageId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// DomainId
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema)]
#[serde(transparent)]
pub struct DomainId(pub Uuid);

impl DomainId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for DomainId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for DomainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for DomainId {
    type Err = uuid::Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(Uuid::parse_str(s)?))
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// MessageStatus  (CHECK: queued, processing, delivered, deferred, bounced,
//                        dropped, scheduled, held)
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
pub enum MessageStatus {
    Queued,
    Processing,
    Delivered,
    Deferred,
    Bounced,
    Dropped,
    Scheduled,
    Held,
}

// ──────────────────────────────────────────────────────────────────────────────
// MessageDirection  (CHECK: inbound, outbound)
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
pub enum MessageDirection {
    Inbound,
    Outbound,
}

// ──────────────────────────────────────────────────────────────────────────────
// Envelope  (SMTP envelope shared by smtp-server, smtp-client, queue)
// ──────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub mail_from: String,
    pub rcpt_to: Vec<String>,
}

// ──────────────────────────────────────────────────────────────────────────────
// AttachmentDisposition  (CHECK: attachment, inline)
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
pub enum AttachmentDisposition {
    Attachment,
    Inline,
}

// ──────────────────────────────────────────────────────────────────────────────
// ScanStatus  (CHECK: pending, clean, infected, error)
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
pub enum ScanStatus {
    Pending,
    Clean,
    Infected,
    Error,
}

// ──────────────────────────────────────────────────────────────────────────────
// SuppressionReason  (CHECK: hard_bounce, complaint, manual, unsubscribe)
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
pub enum SuppressionReason {
    HardBounce,
    Complaint,
    Manual,
    Unsubscribe,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn message_id_is_v7() {
        let a = MessageId::new();
        let b = MessageId::new();
        // UUIDv7 is time-ordered, so b >= a
        assert!(b.0 >= a.0);
    }

    #[test]
    fn message_id_roundtrip() {
        let id = MessageId::new();
        let s = id.to_string();
        let parsed: MessageId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn domain_id_roundtrip() {
        let id = DomainId::new();
        let s = id.to_string();
        let parsed: DomainId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn message_status_display() {
        assert_eq!(MessageStatus::Queued.to_string(), "queued");
        assert_eq!(MessageStatus::Processing.to_string(), "processing");
        assert_eq!(MessageStatus::Delivered.to_string(), "delivered");
        assert_eq!(MessageStatus::Deferred.to_string(), "deferred");
        assert_eq!(MessageStatus::Bounced.to_string(), "bounced");
        assert_eq!(MessageStatus::Dropped.to_string(), "dropped");
        assert_eq!(MessageStatus::Scheduled.to_string(), "scheduled");
        assert_eq!(MessageStatus::Held.to_string(), "held");
    }

    #[test]
    fn message_status_from_str() {
        assert_eq!(
            "queued".parse::<MessageStatus>().unwrap(),
            MessageStatus::Queued
        );
        assert_eq!(
            "held".parse::<MessageStatus>().unwrap(),
            MessageStatus::Held
        );
        assert!("invalid".parse::<MessageStatus>().is_err());
    }

    #[test]
    fn message_status_serde_roundtrip() {
        let status = MessageStatus::Deferred;
        let json = serde_json::to_string(&status).unwrap();
        assert_eq!(json, "\"deferred\"");
        let parsed: MessageStatus = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, status);
    }

    #[test]
    fn message_direction_display() {
        assert_eq!(MessageDirection::Inbound.to_string(), "inbound");
        assert_eq!(MessageDirection::Outbound.to_string(), "outbound");
    }

    #[test]
    fn envelope_serde_roundtrip() {
        let envelope = Envelope {
            mail_from: "sender@example.com".into(),
            rcpt_to: vec!["a@example.com".into(), "b@example.com".into()],
        };
        let json = serde_json::to_string(&envelope).unwrap();
        let parsed: Envelope = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, envelope);
    }

    #[test]
    fn attachment_disposition_display() {
        assert_eq!(AttachmentDisposition::Attachment.to_string(), "attachment");
        assert_eq!(AttachmentDisposition::Inline.to_string(), "inline");
    }

    #[test]
    fn scan_status_display() {
        assert_eq!(ScanStatus::Pending.to_string(), "pending");
        assert_eq!(ScanStatus::Clean.to_string(), "clean");
        assert_eq!(ScanStatus::Infected.to_string(), "infected");
        assert_eq!(ScanStatus::Error.to_string(), "error");
    }

    #[test]
    fn suppression_reason_display() {
        assert_eq!(SuppressionReason::HardBounce.to_string(), "hard_bounce");
        assert_eq!(SuppressionReason::Complaint.to_string(), "complaint");
        assert_eq!(SuppressionReason::Manual.to_string(), "manual");
        assert_eq!(SuppressionReason::Unsubscribe.to_string(), "unsubscribe");
    }

    #[test]
    fn suppression_reason_from_str() {
        assert_eq!(
            "hard_bounce".parse::<SuppressionReason>().unwrap(),
            SuppressionReason::HardBounce
        );
        assert_eq!(
            "complaint".parse::<SuppressionReason>().unwrap(),
            SuppressionReason::Complaint
        );
        assert!("invalid".parse::<SuppressionReason>().is_err());
    }
}
