use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

macro_rules! define_id {
    ($name:ident, v4) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::new_v4())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Uuid::parse_str(s)?))
            }
        }
    };
    ($name:ident, v7) => {
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, utoipa::ToSchema,
        )]
        #[serde(transparent)]
        pub struct $name(pub Uuid);

        impl $name {
            pub fn new() -> Self {
                Self(Uuid::now_v7())
            }
        }

        impl Default for $name {
            fn default() -> Self {
                Self::new()
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                self.0.fmt(f)
            }
        }

        impl FromStr for $name {
            type Err = uuid::Error;
            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Ok(Self(Uuid::parse_str(s)?))
            }
        }
    };
}

define_id!(ApiKeyId, v4);
define_id!(DkimKeyId, v4);
define_id!(IpPoolId, v4);
define_id!(SmtpCredentialId, v4);
define_id!(SuppressionId, v4);
define_id!(InboundRouteId, v4);
define_id!(WarmupScheduleId, v4);
define_id!(MessageEventId, v7);
define_id!(EngagementEventId, v7);
define_id!(AttachmentId, v7);
define_id!(WebhookDeliveryLogId, v4);
define_id!(InboundRouteDeliveryLogId, v4);
define_id!(OAuthClientId, v4);
define_id!(OAuthTokenId, v4);
define_id!(DmarcReportId, v4);
define_id!(FblReportId, v4);
define_id!(PendingUploadId, v4);
define_id!(TlsrptReportId, v4);
define_id!(TrackingDomainId, v4);
define_id!(TrackingCertificateId, v4);
define_id!(ErrorEventId, v4);
define_id!(MailboxId, v4);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_display_roundtrip() {
        let id = ApiKeyId::new();
        let s = id.to_string();
        let parsed: ApiKeyId = s.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn id_serde_roundtrip() {
        let id = DkimKeyId::new();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: DkimKeyId = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn id_from_str_invalid() {
        assert!("not-a-uuid".parse::<IpPoolId>().is_err());
    }
}
