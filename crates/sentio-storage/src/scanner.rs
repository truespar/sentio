use std::time::Duration;

use clamav_client::tokio::Tcp;
use tracing::instrument;

use sentio_core::error::SentioError;
use sentio_core::traits::{ScanResult, VirusScanner};

pub struct ClamAvScanner {
    host: String,
    timeout: Duration,
    max_size_bytes: u64,
}

impl ClamAvScanner {
    pub fn new(host: &str, timeout_secs: u64, max_attachment_size_mb: u32) -> Self {
        Self {
            host: host.to_string(),
            timeout: Duration::from_secs(timeout_secs),
            max_size_bytes: u64::from(max_attachment_size_mb) * 1024 * 1024,
        }
    }

    fn tcp(&self) -> Tcp<&str> {
        Tcp {
            host_address: self.host.as_str(),
        }
    }

    /// Health check - returns Ok(()) if clamd responds to PING.
    pub async fn ping(&self) -> Result<(), SentioError> {
        let response = tokio::time::timeout(self.timeout, clamav_client::tokio::ping(self.tcp()))
            .await
            .map_err(|_| SentioError::Storage("ClamAV ping timed out".into()))?
            .map_err(|e| SentioError::Storage(format!("ClamAV ping failed: {e}")))?;

        let text = String::from_utf8_lossy(&response);
        if text.contains("PONG") {
            Ok(())
        } else {
            Err(SentioError::Storage(format!(
                "ClamAV ping unexpected response: {text}"
            )))
        }
    }
}

/// Parse the raw response from ClamAV INSTREAM protocol.
pub(crate) fn parse_response(response: &[u8]) -> ScanResult {
    let text = String::from_utf8_lossy(response);
    let trimmed = text.trim().trim_end_matches('\0');

    if trimmed.ends_with("OK") {
        ScanResult::Clean
    } else if let Some(found) = trimmed.strip_suffix("FOUND") {
        let virus_name = found.rsplit(':').next().unwrap_or(found).trim().to_string();
        ScanResult::Infected(virus_name)
    } else if trimmed.contains("ERROR") {
        ScanResult::Error(trimmed.to_string())
    } else {
        ScanResult::Error(format!("unexpected ClamAV response: {trimmed}"))
    }
}

impl VirusScanner for ClamAvScanner {
    #[instrument(skip(self, data), name = "clamav.scan", fields(data_len = data.len()))]
    async fn scan(&self, data: &[u8]) -> Result<ScanResult, SentioError> {
        if data.len() as u64 > self.max_size_bytes {
            return Err(SentioError::Validation(format!(
                "attachment size {} bytes exceeds maximum {} bytes",
                data.len(),
                self.max_size_bytes
            )));
        }

        let response = tokio::time::timeout(
            self.timeout,
            clamav_client::tokio::scan_buffer(data, self.tcp(), None::<usize>),
        )
        .await
        .map_err(|_| SentioError::Storage("ClamAV scan timed out".into()))?
        .map_err(|e| SentioError::Storage(format!("ClamAV scan failed: {e}")))?;

        Ok(parse_response(&response))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_clean_response() {
        let resp = b"stream: OK\0";
        assert_eq!(parse_response(resp), ScanResult::Clean);
    }

    #[test]
    fn parse_infected_response() {
        let resp = b"stream: Eicar-Test-Signature FOUND\0";
        assert_eq!(
            parse_response(resp),
            ScanResult::Infected("Eicar-Test-Signature".into())
        );
    }

    #[test]
    fn parse_error_response() {
        let resp = b"stream: ERROR something went wrong\0";
        match parse_response(resp) {
            ScanResult::Error(msg) => assert!(msg.contains("ERROR")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn parse_unexpected_response() {
        let resp = b"something unexpected";
        match parse_response(resp) {
            ScanResult::Error(msg) => assert!(msg.contains("unexpected")),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn size_validation() {
        let scanner = ClamAvScanner::new("127.0.0.1:3310", 30, 1); // 1 MB max
        let data = vec![0u8; 2 * 1024 * 1024]; // 2 MB

        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = rt.block_on(scanner.scan(&data));

        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("exceeds maximum"), "{err}");
    }
}
