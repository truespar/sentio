pub mod dead_letter;
pub mod delivery;
pub mod dispatcher;
pub mod signing;

pub mod test_receiver;

pub use dispatcher::{ReqwestSender, SendResult, WebhookDispatcher, WebhookEvent, WebhookSender};
pub use signing::{HEADER_EVENT, HEADER_NONCE, HEADER_SIGNATURE, HEADER_TIMESTAMP};

use std::sync::Arc;

use sentio_core::traits::{WebhookDeliveryLogRepository, WebhookRepository};
use sentio_queue::{HandlerResult, MessageHandler, QueueMessage};

/// Queue message handler that consumes webhook events from the
/// [`sentio_queue::QUEUE_EVENTS_WEBHOOK`] queue and dispatches them to
/// matching webhook endpoints.
pub struct WebhookEventHandler<S, W, L> {
    dispatcher: Arc<WebhookDispatcher<S, W, L>>,
}

impl<S, W, L> WebhookEventHandler<S, W, L>
where
    S: WebhookSender + 'static,
    W: WebhookRepository + 'static,
    L: WebhookDeliveryLogRepository + 'static,
{
    pub fn new(dispatcher: Arc<WebhookDispatcher<S, W, L>>) -> Self {
        Self { dispatcher }
    }
}

impl<S, W, L> MessageHandler for WebhookEventHandler<S, W, L>
where
    S: WebhookSender + 'static,
    W: WebhookRepository + 'static,
    L: WebhookDeliveryLogRepository + 'static,
{
    async fn handle(&self, message: QueueMessage) -> HandlerResult {
        let event: WebhookEvent = match serde_json::from_slice(&message.body) {
            Ok(e) => e,
            Err(err) => {
                tracing::error!(error = %err, "invalid webhook event payload - rejecting");
                return HandlerResult::Reject;
            }
        };

        match self.dispatcher.dispatch_event(&event).await {
            Ok(()) => HandlerResult::Ack,
            Err(err) => {
                tracing::warn!(error = %err, "webhook dispatch had failures - acking");
                // Ack anyway: the dispatcher already logged individual delivery
                // failures and incremented failure counters. Re-processing the
                // queue message would re-send to webhooks that already succeeded.
                HandlerResult::Ack
            }
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use sentio_core::error::SentioError;
    use sentio_core::ids::WebhookDeliveryLogId;
    use sentio_core::tenant::TenantId;
    use sentio_core::traits::{NewWebhookDeliveryLog, WebhookDeliveryLogRecord, WebhookRecord};
    use sentio_core::webhook::{WebhookId, WebhookStatus};
    use std::sync::Mutex;

    // ── Mock WebhookSender ──────────────────────────────────────────────────

    struct MockSender {
        responses: Mutex<Vec<Result<SendResult, String>>>,
        requests: Mutex<Vec<(String, Vec<u8>)>>,
    }

    impl MockSender {
        fn new(responses: Vec<Result<SendResult, String>>) -> Self {
            Self {
                responses: Mutex::new(responses),
                requests: Mutex::new(Vec::new()),
            }
        }

        fn request_count(&self) -> usize {
            self.requests.lock().unwrap().len()
        }
    }

    impl WebhookSender for MockSender {
        async fn send(
            &self,
            url: &str,
            _headers: Vec<(&str, String)>,
            body: Vec<u8>,
        ) -> Result<SendResult, String> {
            self.requests.lock().unwrap().push((url.to_string(), body));
            let mut responses = self.responses.lock().unwrap();
            if responses.is_empty() {
                Err("no more mock responses".into())
            } else {
                responses.remove(0)
            }
        }
    }

    // ── Mock WebhookRepository ──────────────────────────────────────────────

    struct MockWebhookRepo {
        webhooks: Mutex<Vec<WebhookRecord>>,
        success_calls: Mutex<Vec<WebhookId>>,
        failure_calls: Mutex<Vec<WebhookId>>,
        status_updates: Mutex<Vec<(WebhookId, WebhookStatus)>>,
    }

    impl MockWebhookRepo {
        fn new(webhooks: Vec<WebhookRecord>) -> Self {
            Self {
                webhooks: Mutex::new(webhooks),
                success_calls: Mutex::new(Vec::new()),
                failure_calls: Mutex::new(Vec::new()),
                status_updates: Mutex::new(Vec::new()),
            }
        }
    }

    impl WebhookRepository for MockWebhookRepo {
        async fn create(
            &self,
            _webhook: sentio_core::traits::NewWebhook,
        ) -> Result<WebhookId, SentioError> {
            unimplemented!()
        }

        async fn get(&self, id: WebhookId) -> Result<WebhookRecord, SentioError> {
            let webhooks = self.webhooks.lock().unwrap();
            webhooks
                .iter()
                .find(|w| w.id == id)
                .cloned()
                .ok_or(SentioError::NotFound {
                    entity: "webhook",
                    id: id.to_string(),
                })
        }

        async fn list_by_tenant(
            &self,
            tenant_id: TenantId,
        ) -> Result<Vec<WebhookRecord>, SentioError> {
            let webhooks = self.webhooks.lock().unwrap();
            Ok(webhooks
                .iter()
                .filter(|w| w.tenant_id == tenant_id)
                .cloned()
                .collect())
        }

        async fn update(
            &self,
            _id: WebhookId,
            _update: sentio_core::traits::WebhookUpdate,
        ) -> Result<(), SentioError> {
            unimplemented!()
        }

        async fn update_status(
            &self,
            id: WebhookId,
            status: WebhookStatus,
        ) -> Result<(), SentioError> {
            self.status_updates.lock().unwrap().push((id, status));
            let mut webhooks = self.webhooks.lock().unwrap();
            if let Some(w) = webhooks.iter_mut().find(|w| w.id == id) {
                w.status = status;
            }
            Ok(())
        }

        async fn increment_failure(&self, id: WebhookId) -> Result<(), SentioError> {
            self.failure_calls.lock().unwrap().push(id);
            let mut webhooks = self.webhooks.lock().unwrap();
            if let Some(w) = webhooks.iter_mut().find(|w| w.id == id) {
                w.failure_count += 1;
            }
            Ok(())
        }

        async fn record_success(&self, id: WebhookId) -> Result<(), SentioError> {
            self.success_calls.lock().unwrap().push(id);
            let mut webhooks = self.webhooks.lock().unwrap();
            if let Some(w) = webhooks.iter_mut().find(|w| w.id == id) {
                w.failure_count = 0;
            }
            Ok(())
        }

        async fn delete(&self, _id: WebhookId) -> Result<(), SentioError> {
            unimplemented!()
        }
    }

    // ── Mock WebhookDeliveryLogRepository ───────────────────────────────────

    struct MockDeliveryLogRepo {
        logs: Mutex<Vec<NewWebhookDeliveryLog>>,
    }

    impl MockDeliveryLogRepo {
        fn new() -> Self {
            Self {
                logs: Mutex::new(Vec::new()),
            }
        }

        fn log_count(&self) -> usize {
            self.logs.lock().unwrap().len()
        }
    }

    impl WebhookDeliveryLogRepository for MockDeliveryLogRepo {
        async fn insert(
            &self,
            log: NewWebhookDeliveryLog,
        ) -> Result<WebhookDeliveryLogId, SentioError> {
            self.logs.lock().unwrap().push(log);
            Ok(WebhookDeliveryLogId::new())
        }

        async fn get(
            &self,
            _id: WebhookDeliveryLogId,
        ) -> Result<WebhookDeliveryLogRecord, SentioError> {
            unimplemented!()
        }

        async fn list_by_webhook(
            &self,
            _webhook_id: WebhookId,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<WebhookDeliveryLogRecord>, SentioError> {
            unimplemented!()
        }

        async fn list_by_tenant(
            &self,
            _tenant_id: TenantId,
            _limit: i64,
            _offset: i64,
        ) -> Result<Vec<WebhookDeliveryLogRecord>, SentioError> {
            unimplemented!()
        }
    }

    // ── Helpers ─────────────────────────────────────────────────────────────

    fn test_tenant_id() -> TenantId {
        "00000000-0000-0000-0000-000000000001".parse().unwrap()
    }

    fn test_webhook(
        id: &str,
        tenant_id: TenantId,
        event_types: Vec<&str>,
        status: WebhookStatus,
        failure_count: i32,
    ) -> WebhookRecord {
        WebhookRecord {
            id: id.parse().unwrap(),
            tenant_id,
            url: format!("https://example.com/webhook/{}", id.chars().last().unwrap()),
            event_types: event_types.into_iter().map(String::from).collect(),
            signing_secret: "whsec_test".into(),
            status,
            failure_count,
            last_success_at: None,
            last_failure_at: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }
    }

    fn test_event(tenant_id: TenantId, event_type: &str) -> WebhookEvent {
        WebhookEvent {
            tenant_id: tenant_id.to_string(),
            event_type: event_type.into(),
            message_id: Some("msg-1".into()),
            payload: serde_json::json!({"status": event_type}),
            occurred_at: None,
        }
    }

    // ── Tests ───────────────────────────────────────────────────────────────

    #[tokio::test]
    async fn dispatch_to_matching_webhook() {
        let tid = test_tenant_id();
        let wh = test_webhook(
            "00000000-0000-0000-0000-000000000010",
            tid,
            vec!["delivered"],
            WebhookStatus::Active,
            0,
        );

        let sender = Arc::new(MockSender::new(vec![Ok(SendResult {
            status: 200,
            body: Some("ok".into()),
        })]));
        let webhook_repo = Arc::new(MockWebhookRepo::new(vec![wh]));
        let log_repo = Arc::new(MockDeliveryLogRepo::new());

        let dispatcher =
            WebhookDispatcher::new(sender.clone(), webhook_repo.clone(), log_repo.clone());

        let event = test_event(tid, "delivered");
        let result = dispatcher.dispatch_event(&event).await;

        assert!(result.is_ok());
        assert_eq!(sender.request_count(), 1);
        assert_eq!(log_repo.log_count(), 1);
        assert_eq!(webhook_repo.success_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn skip_paused_webhooks() {
        let tid = test_tenant_id();
        let wh = test_webhook(
            "00000000-0000-0000-0000-000000000010",
            tid,
            vec!["delivered"],
            WebhookStatus::Paused,
            0,
        );

        let sender = Arc::new(MockSender::new(vec![]));
        let webhook_repo = Arc::new(MockWebhookRepo::new(vec![wh]));
        let log_repo = Arc::new(MockDeliveryLogRepo::new());

        let dispatcher = WebhookDispatcher::new(sender.clone(), webhook_repo, log_repo.clone());

        let event = test_event(tid, "delivered");
        let result = dispatcher.dispatch_event(&event).await;

        assert!(result.is_ok());
        assert_eq!(sender.request_count(), 0);
        assert_eq!(log_repo.log_count(), 0);
    }

    #[tokio::test]
    async fn skip_non_matching_event_types() {
        let tid = test_tenant_id();
        let wh = test_webhook(
            "00000000-0000-0000-0000-000000000010",
            tid,
            vec!["bounced"],
            WebhookStatus::Active,
            0,
        );

        let sender = Arc::new(MockSender::new(vec![]));
        let webhook_repo = Arc::new(MockWebhookRepo::new(vec![wh]));
        let log_repo = Arc::new(MockDeliveryLogRepo::new());

        let dispatcher = WebhookDispatcher::new(sender.clone(), webhook_repo, log_repo);

        let event = test_event(tid, "delivered");
        let result = dispatcher.dispatch_event(&event).await;

        assert!(result.is_ok());
        assert_eq!(sender.request_count(), 0);
    }

    #[tokio::test]
    async fn wildcard_event_type_matches_all() {
        let tid = test_tenant_id();
        let wh = test_webhook(
            "00000000-0000-0000-0000-000000000010",
            tid,
            vec!["*"],
            WebhookStatus::Active,
            0,
        );

        let sender = Arc::new(MockSender::new(vec![Ok(SendResult {
            status: 200,
            body: None,
        })]));
        let webhook_repo = Arc::new(MockWebhookRepo::new(vec![wh]));
        let log_repo = Arc::new(MockDeliveryLogRepo::new());

        let dispatcher = WebhookDispatcher::new(sender.clone(), webhook_repo, log_repo);

        let event = test_event(tid, "some_custom_event");
        assert!(dispatcher.dispatch_event(&event).await.is_ok());
        assert_eq!(sender.request_count(), 1);
    }

    #[tokio::test]
    async fn http_failure_triggers_retries_and_failure_tracking() {
        let tid = test_tenant_id();
        let wh = test_webhook(
            "00000000-0000-0000-0000-000000000010",
            tid,
            vec!["delivered"],
            WebhookStatus::Active,
            0,
        );

        // "delivered" is critical → 3 quick retry attempts. All fail.
        let sender = Arc::new(MockSender::new(vec![
            Ok(SendResult {
                status: 500,
                body: Some("error".into()),
            }),
            Ok(SendResult {
                status: 502,
                body: None,
            }),
            Ok(SendResult {
                status: 503,
                body: None,
            }),
        ]));
        let webhook_repo = Arc::new(MockWebhookRepo::new(vec![wh]));
        let log_repo = Arc::new(MockDeliveryLogRepo::new());

        let dispatcher =
            WebhookDispatcher::new(sender.clone(), webhook_repo.clone(), log_repo.clone());

        let event = test_event(tid, "delivered");
        let result = dispatcher.dispatch_event(&event).await;

        assert!(result.is_err());
        assert_eq!(sender.request_count(), 3); // 3 attempts for critical event
        assert_eq!(log_repo.log_count(), 3); // each attempt logged
        assert_eq!(webhook_repo.failure_calls.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn normal_event_gets_fewer_retries() {
        let tid = test_tenant_id();
        let wh = test_webhook(
            "00000000-0000-0000-0000-000000000010",
            tid,
            vec!["queued"],
            WebhookStatus::Active,
            0,
        );

        // "queued" is normal → 2 quick retry attempts.
        let sender = Arc::new(MockSender::new(vec![
            Err("connection refused".into()),
            Err("connection refused".into()),
        ]));
        let webhook_repo = Arc::new(MockWebhookRepo::new(vec![wh]));
        let log_repo = Arc::new(MockDeliveryLogRepo::new());

        let dispatcher = WebhookDispatcher::new(sender.clone(), webhook_repo, log_repo);

        let event = test_event(tid, "queued");
        let result = dispatcher.dispatch_event(&event).await;

        assert!(result.is_err());
        assert_eq!(sender.request_count(), 2); // only 2 attempts for normal event
    }

    #[tokio::test]
    async fn retry_succeeds_on_second_attempt() {
        let tid = test_tenant_id();
        let wh = test_webhook(
            "00000000-0000-0000-0000-000000000010",
            tid,
            vec!["delivered"],
            WebhookStatus::Active,
            0,
        );

        let sender = Arc::new(MockSender::new(vec![
            Ok(SendResult {
                status: 503,
                body: None,
            }),
            Ok(SendResult {
                status: 200,
                body: Some("ok".into()),
            }),
        ]));
        let webhook_repo = Arc::new(MockWebhookRepo::new(vec![wh]));
        let log_repo = Arc::new(MockDeliveryLogRepo::new());

        let dispatcher = WebhookDispatcher::new(sender.clone(), webhook_repo.clone(), log_repo);

        let event = test_event(tid, "delivered");
        let result = dispatcher.dispatch_event(&event).await;

        assert!(result.is_ok());
        assert_eq!(sender.request_count(), 2);
        assert_eq!(webhook_repo.success_calls.lock().unwrap().len(), 1);
        assert!(webhook_repo.failure_calls.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn auto_disable_after_threshold() {
        let tid = test_tenant_id();
        let wh = test_webhook(
            "00000000-0000-0000-0000-000000000010",
            tid,
            vec!["delivered"],
            WebhookStatus::Active,
            dead_letter::AUTO_DISABLE_THRESHOLD - 1, // one away from threshold
        );

        // All attempts fail.
        let sender = Arc::new(MockSender::new(vec![
            Ok(SendResult {
                status: 500,
                body: None,
            }),
            Ok(SendResult {
                status: 500,
                body: None,
            }),
            Ok(SendResult {
                status: 500,
                body: None,
            }),
        ]));
        let webhook_repo = Arc::new(MockWebhookRepo::new(vec![wh]));
        let log_repo = Arc::new(MockDeliveryLogRepo::new());

        let dispatcher = WebhookDispatcher::new(sender, webhook_repo.clone(), log_repo);

        let event = test_event(tid, "delivered");
        let _ = dispatcher.dispatch_event(&event).await;

        // increment_failure bumps count to threshold → auto-disable triggered.
        let updates = webhook_repo.status_updates.lock().unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].1, WebhookStatus::Disabled);
    }

    #[tokio::test]
    async fn multiple_webhooks_fan_out() {
        let tid = test_tenant_id();
        let wh1 = test_webhook(
            "00000000-0000-0000-0000-000000000010",
            tid,
            vec!["delivered"],
            WebhookStatus::Active,
            0,
        );
        let wh2 = test_webhook(
            "00000000-0000-0000-0000-000000000020",
            tid,
            vec!["delivered", "bounced"],
            WebhookStatus::Active,
            0,
        );

        let sender = Arc::new(MockSender::new(vec![
            Ok(SendResult {
                status: 200,
                body: None,
            }),
            Ok(SendResult {
                status: 200,
                body: None,
            }),
        ]));
        let webhook_repo = Arc::new(MockWebhookRepo::new(vec![wh1, wh2]));
        let log_repo = Arc::new(MockDeliveryLogRepo::new());

        let dispatcher = WebhookDispatcher::new(sender.clone(), webhook_repo, log_repo);

        let event = test_event(tid, "delivered");
        assert!(dispatcher.dispatch_event(&event).await.is_ok());
        assert_eq!(sender.request_count(), 2);
    }

    #[tokio::test]
    async fn webhook_event_serde_roundtrip() {
        let event = WebhookEvent {
            tenant_id: "00000000-0000-0000-0000-000000000001".into(),
            event_type: "delivered".into(),
            message_id: Some("msg-1".into()),
            payload: serde_json::json!({"recipient": "user@example.com"}),
            occurred_at: Some("2024-01-01T00:00:00Z".into()),
        };

        let json = serde_json::to_vec(&event).unwrap();
        let parsed: WebhookEvent = serde_json::from_slice(&json).unwrap();

        assert_eq!(parsed.tenant_id, event.tenant_id);
        assert_eq!(parsed.event_type, event.event_type);
        assert_eq!(parsed.message_id, event.message_id);
        assert_eq!(parsed.payload, event.payload);
    }

    #[tokio::test]
    async fn handler_rejects_invalid_payload() {
        let sender = Arc::new(MockSender::new(vec![]));
        let webhook_repo = Arc::new(MockWebhookRepo::new(vec![]));
        let log_repo = Arc::new(MockDeliveryLogRepo::new());

        let dispatcher = Arc::new(WebhookDispatcher::new(sender, webhook_repo, log_repo));

        let handler = WebhookEventHandler::new(dispatcher);
        let message = QueueMessage {
            body: b"not valid json".to_vec(),
            headers: Default::default(),
        };

        let result = handler.handle(message).await;
        assert!(matches!(result, HandlerResult::Reject));
    }

    #[tokio::test]
    async fn handler_acks_successful_dispatch() {
        let tid = test_tenant_id();
        let wh = test_webhook(
            "00000000-0000-0000-0000-000000000010",
            tid,
            vec!["delivered"],
            WebhookStatus::Active,
            0,
        );

        let sender = Arc::new(MockSender::new(vec![Ok(SendResult {
            status: 200,
            body: None,
        })]));
        let webhook_repo = Arc::new(MockWebhookRepo::new(vec![wh]));
        let log_repo = Arc::new(MockDeliveryLogRepo::new());

        let dispatcher = Arc::new(WebhookDispatcher::new(sender, webhook_repo, log_repo));

        let handler = WebhookEventHandler::new(dispatcher);
        let event = test_event(tid, "delivered");
        let message = QueueMessage {
            body: serde_json::to_vec(&event).unwrap(),
            headers: Default::default(),
        };

        let result = handler.handle(message).await;
        assert!(matches!(result, HandlerResult::Ack));
    }
}
