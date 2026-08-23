use std::sync::{Arc, Mutex};

use sentio_core::error::SentioError;

use crate::producer::{PublishHeaders, QueuePublisher};

/// A captured publish call for test assertions.
#[derive(Debug, Clone)]
pub struct PublishedMessage {
    pub exchange: String,
    pub routing_key: String,
    pub payload: Vec<u8>,
    pub headers: PublishHeaders,
}

/// In-memory publisher for unit tests. Records all published messages.
#[derive(Clone)]
pub struct MockPublisher {
    messages: Arc<Mutex<Vec<PublishedMessage>>>,
}

impl MockPublisher {
    pub fn new() -> Self {
        Self {
            messages: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Return a snapshot of all published messages.
    pub fn published(&self) -> Vec<PublishedMessage> {
        self.messages.lock().unwrap().clone()
    }

    /// Number of published messages.
    pub fn published_count(&self) -> usize {
        self.messages.lock().unwrap().len()
    }

    /// Discard all recorded messages.
    pub fn clear(&self) {
        self.messages.lock().unwrap().clear();
    }
}

impl Default for MockPublisher {
    fn default() -> Self {
        Self::new()
    }
}

impl QueuePublisher for MockPublisher {
    async fn publish(
        &self,
        exchange: &str,
        routing_key: &str,
        payload: &[u8],
        headers: PublishHeaders,
    ) -> Result<(), SentioError> {
        self.messages.lock().unwrap().push(PublishedMessage {
            exchange: exchange.to_string(),
            routing_key: routing_key.to_string(),
            payload: payload.to_vec(),
            headers,
        });
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn mock_records_messages() {
        let mock = MockPublisher::new();

        mock.publish(
            "test.exchange",
            "test.key",
            b"hello",
            PublishHeaders::default(),
        )
        .await
        .unwrap();

        assert_eq!(mock.published_count(), 1);
        let msgs = mock.published();
        assert_eq!(msgs[0].exchange, "test.exchange");
        assert_eq!(msgs[0].routing_key, "test.key");
        assert_eq!(msgs[0].payload, b"hello");
    }

    #[tokio::test]
    async fn mock_clear_works() {
        let mock = MockPublisher::new();

        mock.publish("ex", "rk", b"data", PublishHeaders::default())
            .await
            .unwrap();
        assert_eq!(mock.published_count(), 1);

        mock.clear();
        assert_eq!(mock.published_count(), 0);
    }
}
