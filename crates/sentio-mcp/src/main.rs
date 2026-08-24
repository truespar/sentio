use rmcp::ServiceExt;
use sentio_mcp::{SentioClient, SentioMcpServer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "warn".into()),
        )
        .init();

    let base_url =
        std::env::var("SENTIO_BASE_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let api_key = std::env::var("SENTIO_API_KEY")
        .map_err(|_| "SENTIO_API_KEY environment variable is required")?;

    let server = SentioMcpServer::new(SentioClient::new(base_url, api_key));
    let service = server.serve(rmcp::transport::stdio()).await?;
    service.waiting().await?;
    Ok(())
}
