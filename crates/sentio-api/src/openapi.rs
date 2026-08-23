use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
use utoipa::{Modify, OpenApi};

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Sentio SMTP API",
        version = "1.0.0",
        description = "Multi-tenant SMTP platform API",
    ),
    paths(
        // Messages
        crate::routes::messages::send_message,
        crate::routes::messages::send_batch,
        crate::routes::messages::send_raw,
        crate::routes::messages::list_messages,
        crate::routes::messages::get_message,
        crate::routes::messages::get_message_raw,
        crate::routes::messages::get_message_events,
        // Attachments
        crate::routes::attachments::list_attachments,
        crate::routes::attachments::download_attachment,
        // Domains
        crate::routes::domains::create_domain,
        crate::routes::domains::list_domains,
        crate::routes::domains::get_domain,
        crate::routes::domains::update_domain,
        crate::routes::domains::delete_domain,
        crate::routes::domains::verify_domain,
        crate::routes::domains::get_dns_records,
        // Mailboxes
        crate::routes::mailboxes::list_mailboxes,
        crate::routes::mailboxes::create_mailbox,
        crate::routes::mailboxes::get_mailbox,
        crate::routes::mailboxes::update_mailbox,
        crate::routes::mailboxes::delete_mailbox,
        // DKIM Keys
        crate::routes::dkim_keys::create_dkim_key,
        crate::routes::dkim_keys::list_dkim_keys,
        crate::routes::dkim_keys::rotate_dkim_key,
        crate::routes::dkim_keys::retire_dkim_key,
        crate::routes::dkim_keys::get_dkim_dns_record,
        // Webhooks
        crate::routes::webhooks::create_webhook,
        crate::routes::webhooks::list_webhooks,
        crate::routes::webhooks::get_webhook,
        crate::routes::webhooks::update_webhook,
        crate::routes::webhooks::delete_webhook,
        crate::routes::webhooks::test_webhook,
        crate::routes::webhooks::list_deliveries,
        // Suppressions
        crate::routes::suppressions::add_suppression,
        crate::routes::suppressions::list_suppressions,
        crate::routes::suppressions::get_suppression,
        crate::routes::suppressions::remove_suppression,
        crate::routes::suppressions::check_suppression,
        // Tenants
        crate::routes::tenants::create_tenant,
        crate::routes::tenants::list_tenants,
        crate::routes::tenants::get_tenant,
        crate::routes::tenants::update_tenant_status,
        crate::routes::tenants::update_tenant,
        crate::routes::tenants::delete_tenant,
        // API Keys
        crate::routes::api_keys::create_api_key,
        crate::routes::api_keys::list_api_keys,
        crate::routes::api_keys::revoke_api_key,
        // SMTP Credentials
        crate::routes::smtp_credentials::create_smtp_credential,
        crate::routes::smtp_credentials::list_smtp_credentials,
        crate::routes::smtp_credentials::update_smtp_credential_enabled,
        crate::routes::smtp_credentials::delete_smtp_credential,
        // Inbound Routes
        crate::routes::inbound_routes::create_inbound_route,
        crate::routes::inbound_routes::list_inbound_routes,
        crate::routes::inbound_routes::update_inbound_route,
        crate::routes::inbound_routes::delete_inbound_route,
        // IP Pools
        crate::routes::ip_pools::create_ip_pool,
        crate::routes::ip_pools::list_ip_pools,
        crate::routes::ip_pools::get_ip_pool,
        crate::routes::ip_pools::update_ip_pool_status,
        crate::routes::ip_pools::add_ips,
        crate::routes::ip_pools::remove_ips,
        crate::routes::ip_pools::delete_ip_pool,
        crate::routes::ip_pools::list_pool_tenants,
        crate::routes::ip_pools::list_tenant_pools,
        crate::routes::ip_pools::assign_ip_pool,
        crate::routes::ip_pools::update_assignment_priority,
        crate::routes::ip_pools::unassign_ip_pool,
        // Queues
        crate::routes::queues::queue_stats,
        crate::routes::queues::pause_queue,
        crate::routes::queues::resume_queue,
        crate::routes::queues::list_deferred,
        // Analytics
        crate::routes::analytics::overview,
        crate::routes::analytics::delivery,
        crate::routes::analytics::engagement,
        crate::routes::analytics::bounces,
        // Reputation
        crate::routes::reputation::list_domain_reputations,
        crate::routes::reputation::get_domain_reputation,
        crate::routes::reputation::get_ip_reputation,
        // Spam Training
        crate::routes::spam::train_ham,
        crate::routes::spam::train_spam,
        // Reports
        crate::routes::spam::list_dmarc_reports,
        crate::routes::spam::get_dmarc_report,
        crate::routes::spam::list_fbl_reports,
        crate::routes::spam::get_fbl_report,
        crate::routes::spam::process_fbl_report,
        crate::routes::spam::list_tlsrpt_reports,
        crate::routes::spam::get_tlsrpt_report,
        // OAuth
        crate::routes::oauth::create_oauth_client,
        crate::routes::oauth::list_oauth_clients,
        crate::routes::oauth::get_oauth_client,
        crate::routes::oauth::revoke_oauth_client,
        crate::routes::oauth::delete_oauth_client,
        // Errors
        crate::routes::errors::list_errors,
        crate::routes::errors::error_summary,
        crate::routes::errors::get_error,
        // Abuse
        crate::routes::abuse::list_bans,
        crate::routes::abuse::create_ban,
        crate::routes::abuse::delete_ban,
        crate::routes::abuse::list_whitelist,
        crate::routes::abuse::create_whitelist,
        crate::routes::abuse::delete_whitelist,
        crate::routes::abuse::get_reputation,
        crate::routes::abuse::reset_reputation,
        // Tracking
        crate::routes::tracking::track_open,
        crate::routes::tracking::track_click,
        // Tracking Domains
        crate::routes::tracking_domains::create_tracking_domain,
        crate::routes::tracking_domains::list_tracking_domains,
        crate::routes::tracking_domains::get_tracking_domain,
        crate::routes::tracking_domains::verify_tracking_domain,
        crate::routes::tracking_domains::delete_tracking_domain,
        crate::routes::tracking_domains::get_certificate,
        crate::routes::tracking_domains::upload_certificate,
        // Health
        crate::routes::health::liveness,
        crate::routes::health::readiness,
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "Messages", description = "Send and retrieve email messages"),
        (name = "Domains", description = "Domain management and verification"),
        (name = "Mailboxes", description = "Mailbox management"),
        (name = "DKIM Keys", description = "DKIM key management"),
        (name = "Webhooks", description = "Webhook configuration and delivery logs"),
        (name = "Suppressions", description = "Email suppression list management"),
        (name = "Tenants", description = "Tenant management"),
        (name = "API Keys", description = "API key management"),
        (name = "SMTP Credentials", description = "SMTP credential management"),
        (name = "Inbound Routes", description = "Inbound email routing configuration"),
        (name = "IP Pools", description = "IP pool management and assignment"),
        (name = "Queues", description = "Queue management and monitoring"),
        (name = "Analytics", description = "Email analytics and statistics"),
        (name = "Reputation", description = "Domain and IP reputation monitoring"),
        (name = "Spam Training", description = "Spam filter training"),
        (name = "Reports", description = "DMARC, FBL, and TLS-RPT reports"),
        (name = "OAuth", description = "OAuth client management"),
        (name = "Errors", description = "Error event tracking and monitoring"),
        (name = "Abuse", description = "Abuse management: bans, whitelist, reputation"),
        (name = "Tracking", description = "Open and click tracking endpoints"),
        (name = "Tracking Domains", description = "Custom tracking domain management"),
        (name = "Health", description = "Health check endpoints"),
    ),
)]
pub struct ApiDoc;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        let components = openapi.components.get_or_insert_with(Default::default);
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("API Key")
                    .build(),
            ),
        );
    }
}
