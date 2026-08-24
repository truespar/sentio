//! Sentio MCP server - exposes the Sentio REST API as MCP tools over stdio.

pub mod api;
pub mod tools;

pub use api::{ApiError, SentioClient};
pub use tools::SentioMcpServer;
