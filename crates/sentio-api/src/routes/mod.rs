pub mod abuse;
pub mod analytics;
pub mod api_keys;
pub mod attachments;
pub mod dkim_keys;
pub mod domains;
pub mod errors;
pub mod health;
pub mod inbound_routes;
pub mod ip_pools;
pub mod mailboxes;
pub mod messages;
pub mod oauth;
pub mod queues;
pub mod reputation;
pub mod smtp_credentials;
pub mod spam;
pub mod suppressions;
pub mod tenants;
pub mod tracking;
pub mod tracking_domains;
pub mod webhooks;

use axum::extract::DefaultBodyLimit;
use axum::routing::{delete, get, post, put};
use axum::Json;
use axum::Router;
use tower_http::request_id::{PropagateRequestIdLayer, SetRequestIdLayer};
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_scalar::{Scalar, Servable};

use crate::middleware::UuidRequestId;
use crate::openapi::ApiDoc;
use crate::state::AppState;

/// Build the complete API router with all middleware layers.
pub fn router(state: AppState) -> Router {
    let max_body_bytes = (state.config.server.max_api_body_size_mb as usize) * 1024 * 1024;
    let messages_router = Router::new()
        .route("/send", post(messages::send_message))
        .route("/send-multipart", post(messages::send_multipart))
        .route("/send-batch", post(messages::send_batch))
        .route("/send-raw", post(messages::send_raw))
        .route("/", get(messages::list_messages))
        .route("/{id}", get(messages::get_message))
        .route("/{id}/events", get(messages::get_message_events))
        .route("/{id}/raw", get(messages::get_message_raw))
        .route("/{id}/attachments", get(attachments::list_attachments))
        .route(
            "/{message_id}/attachments/{attachment_id}",
            get(attachments::download_attachment),
        );

    let domains_router = Router::new()
        .route("/", post(domains::create_domain).get(domains::list_domains))
        .route(
            "/{id}",
            get(domains::get_domain)
                .put(domains::update_domain)
                .delete(domains::delete_domain),
        )
        .route("/{id}/verify", post(domains::verify_domain))
        .route("/{id}/dns-check", post(domains::run_dns_check))
        .route("/{id}/dns-records", get(domains::get_dns_records))
        // DKIM keys nested under domains
        .route(
            "/{domain_id}/dkim-keys",
            post(dkim_keys::create_dkim_key).get(dkim_keys::list_dkim_keys),
        )
        .route(
            "/{domain_id}/dkim-keys/rotate",
            post(dkim_keys::rotate_dkim_key),
        )
        .route(
            "/{domain_id}/dkim-keys/{id}",
            delete(dkim_keys::retire_dkim_key),
        )
        .route(
            "/{domain_id}/dkim-keys/{id}/dns-record",
            get(dkim_keys::get_dkim_dns_record),
        )
        // Mailboxes nested under domains
        .route(
            "/{domain_id}/mailboxes",
            post(mailboxes::create_mailbox).get(mailboxes::list_mailboxes),
        )
        .route(
            "/{domain_id}/mailboxes/{id}",
            get(mailboxes::get_mailbox)
                .put(mailboxes::update_mailbox)
                .delete(mailboxes::delete_mailbox),
        );

    let webhooks_router = Router::new()
        .route(
            "/",
            post(webhooks::create_webhook).get(webhooks::list_webhooks),
        )
        .route(
            "/{id}",
            get(webhooks::get_webhook)
                .put(webhooks::update_webhook)
                .delete(webhooks::delete_webhook),
        )
        .route("/{id}/test", post(webhooks::test_webhook))
        .route("/{id}/deliveries", get(webhooks::list_deliveries));

    let queues_router = Router::new()
        .route("/stats", get(queues::queue_stats))
        .route("/pause", post(queues::pause_queue))
        .route("/resume", post(queues::resume_queue))
        .route("/deferred", get(queues::list_deferred));

    let suppressions_router = Router::new()
        .route(
            "/",
            post(suppressions::add_suppression).get(suppressions::list_suppressions),
        )
        .route(
            "/{email}",
            get(suppressions::get_suppression).delete(suppressions::remove_suppression),
        )
        .route("/check", post(suppressions::check_suppression));

    let tenants_router = Router::new()
        .route("/", post(tenants::create_tenant).get(tenants::list_tenants))
        .route(
            "/{id}",
            get(tenants::get_tenant)
                .put(tenants::update_tenant)
                .patch(tenants::update_tenant)
                .delete(tenants::delete_tenant),
        )
        .route("/{id}/status", put(tenants::update_tenant_status))
        .route(
            "/{tenant_id}/ip-pools",
            get(ip_pools::list_tenant_pools).post(ip_pools::assign_ip_pool),
        )
        .route(
            "/{tenant_id}/ip-pools/{pool_id}",
            put(ip_pools::update_assignment_priority).delete(ip_pools::unassign_ip_pool),
        )
        // API keys nested under tenants
        .route(
            "/{tenant_id}/api-keys",
            post(api_keys::create_api_key).get(api_keys::list_api_keys),
        )
        .route(
            "/{tenant_id}/api-keys/{id}",
            delete(api_keys::revoke_api_key),
        )
        // SMTP credentials nested under tenants
        .route(
            "/{tenant_id}/smtp-credentials",
            post(smtp_credentials::create_smtp_credential)
                .get(smtp_credentials::list_smtp_credentials),
        )
        .route(
            "/{tenant_id}/smtp-credentials/{id}",
            delete(smtp_credentials::delete_smtp_credential),
        )
        .route(
            "/{tenant_id}/smtp-credentials/{id}/enabled",
            put(smtp_credentials::update_smtp_credential_enabled),
        )
        // Inbound routes nested under tenants
        .route(
            "/{tenant_id}/inbound-routes",
            post(inbound_routes::create_inbound_route).get(inbound_routes::list_inbound_routes),
        )
        .route(
            "/{tenant_id}/inbound-routes/{id}",
            put(inbound_routes::update_inbound_route)
                .delete(inbound_routes::delete_inbound_route),
        );

    let ip_pools_router = Router::new()
        .route(
            "/",
            post(ip_pools::create_ip_pool).get(ip_pools::list_ip_pools),
        )
        .route(
            "/{id}",
            get(ip_pools::get_ip_pool).delete(ip_pools::delete_ip_pool),
        )
        .route("/{id}/status", put(ip_pools::update_ip_pool_status))
        .route(
            "/{id}/ips",
            post(ip_pools::add_ips).delete(ip_pools::remove_ips),
        )
        .route("/{id}/tenants", get(ip_pools::list_pool_tenants));

    let spam_router = Router::new()
        .route("/train/ham", post(spam::train_ham))
        .route("/train/spam", post(spam::train_spam));

    let reports_router = Router::new()
        .route("/dmarc", get(spam::list_dmarc_reports))
        .route("/dmarc/{id}", get(spam::get_dmarc_report))
        .route("/fbl", get(spam::list_fbl_reports))
        .route("/fbl/{id}", get(spam::get_fbl_report))
        .route("/fbl/{id}/process", post(spam::process_fbl_report))
        .route("/tlsrpt", get(spam::list_tlsrpt_reports))
        .route("/tlsrpt/{id}", get(spam::get_tlsrpt_report));

    let reputation_router = Router::new()
        .route("/domains", get(reputation::list_domain_reputations))
        .route("/domains/{id}", get(reputation::get_domain_reputation))
        .route("/ips/{ip}", get(reputation::get_ip_reputation));

    let analytics_router = Router::new()
        .route("/overview", get(analytics::overview))
        .route("/delivery", get(analytics::delivery))
        .route("/engagement", get(analytics::engagement))
        .route("/bounces", get(analytics::bounces));

    let health_router = Router::new()
        .route("/live", get(health::liveness))
        .route("/ready", get(health::readiness));

    let tracking_router = Router::new()
        .route("/open/{token}", get(tracking::track_open))
        .route("/click/{token}", get(tracking::track_click));

    let tracking_domains_router = Router::new()
        .route(
            "/",
            post(tracking_domains::create_tracking_domain)
                .get(tracking_domains::list_tracking_domains),
        )
        .route(
            "/{id}",
            get(tracking_domains::get_tracking_domain)
                .delete(tracking_domains::delete_tracking_domain),
        )
        .route(
            "/{id}/verify",
            post(tracking_domains::verify_tracking_domain),
        )
        .route(
            "/{id}/certificate",
            get(tracking_domains::get_certificate).post(tracking_domains::upload_certificate),
        );

    let oauth_router = Router::new()
        .route(
            "/clients",
            post(oauth::create_oauth_client).get(oauth::list_oauth_clients),
        )
        .route(
            "/clients/{id}",
            get(oauth::get_oauth_client).delete(oauth::delete_oauth_client),
        )
        .route("/clients/{id}/revoke", post(oauth::revoke_oauth_client));

    let abuse_router = Router::new()
        .route("/bans", get(abuse::list_bans).post(abuse::create_ban))
        .route("/bans/{ip}", delete(abuse::delete_ban))
        .route(
            "/whitelist",
            get(abuse::list_whitelist).post(abuse::create_whitelist),
        )
        .route("/whitelist/{ip}", delete(abuse::delete_whitelist))
        .route("/reputation/{ip}", get(abuse::get_reputation))
        .route("/reputation/{ip}/reset", post(abuse::reset_reputation));

    let errors_router = Router::new()
        .route("/", get(errors::list_errors))
        .route("/summary", get(errors::error_summary))
        .route("/{id}", get(errors::get_error));

    Router::new()
        .route("/openapi.json", get(|| async { Json(ApiDoc::openapi()) }))
        .merge(Scalar::with_url("/docs", ApiDoc::openapi()))
        .nest("/v1/messages", messages_router)
        .nest("/v1/domains", domains_router)
        .nest("/v1/webhooks", webhooks_router)
        .nest("/v1/queues", queues_router)
        .nest("/v1/suppressions", suppressions_router)
        .nest("/v1/tenants", tenants_router)
        .nest("/v1/ip-pools", ip_pools_router)
        .nest("/v1/spam", spam_router)
        .nest("/v1/reports", reports_router)
        .nest("/v1/reputation", reputation_router)
        .nest("/v1/analytics", analytics_router)
        .nest("/v1/tracking-domains", tracking_domains_router)
        .nest("/v1/oauth", oauth_router)
        .nest("/v1/admin/abuse", abuse_router)
        .nest("/v1/admin/errors", errors_router)
        .nest("/health", health_router)
        .nest("/track", tracking_router)
        .layer(DefaultBodyLimit::max(max_body_bytes))
        .layer(TraceLayer::new_for_http())
        .layer(PropagateRequestIdLayer::x_request_id())
        .layer(SetRequestIdLayer::x_request_id(UuidRequestId))
        .with_state(state)
}
