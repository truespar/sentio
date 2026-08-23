pub mod analytics_consumer;
pub mod auth;
pub mod error_capture;
pub mod errors;
pub mod extract;
pub mod middleware;
pub mod openapi;
pub mod response;
pub mod routes;
pub mod server;
pub mod state;

pub use server::start;
pub use state::AppState;

/// Serialize the OpenAPI 3.1 document as pretty-printed JSON.
///
/// Used by the `openapi` subcommand so the specification can be exported for
/// client generation or diffing without starting the server.
pub fn openapi_json_pretty() -> Result<String, serde_json::Error> {
    use utoipa::OpenApi;
    serde_json::to_string_pretty(&openapi::ApiDoc::openapi())
}
