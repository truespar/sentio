use std::path::Path;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use sentio_core::auth::DomainStatus;
use sentio_core::config::load_config;
use sentio_core::error::SentioError;
use sentio_core::traits::{DomainRepository, SmtpCredentialRepository, TenantRepository};
use sentio_observe::init_logging;
use sentio_spam::RspamdScorer;

/// Boxed async callback for IP-based hooks (auth failure/success).
type IpCallback = Arc<
    dyn Fn(std::net::IpAddr) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send
        + Sync,
>;

/// Boxed async callback for connection checks (returns Result).
type ConnectionCheck = Arc<
    dyn Fn(
            std::net::IpAddr,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), ()>> + Send>>
        + Send
        + Sync,
>;

#[derive(Parser)]
#[command(
    name = "sentio-smtp",
    about = "Sentio SMTP - multi-tenant email platform"
)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "config/default.toml", global = true)]
    config: String,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run the SMTP + API server (default when no subcommand is given).
    Serve,
    /// Apply pending database migrations, then exit.
    Migrate,
    /// Print the OpenAPI 3.1 specification as JSON, then exit.
    Openapi,
}

#[tokio::main]
async fn main() {
    // Install the rustls CryptoProvider before any TLS operations.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();

    let cli = Cli::parse();

    // Handled before config loading: the spec is static, so dumping it must not
    // require a config file, a database, or a network.
    if matches!(cli.command, Some(Command::Openapi)) {
        match sentio_api::openapi_json_pretty() {
            Ok(json) => {
                println!("{json}");
                std::process::exit(0);
            }
            Err(e) => {
                eprintln!("fatal: could not serialize OpenAPI spec: {e}");
                std::process::exit(1);
            }
        }
    }

    // Load config before initializing logging so the subscriber
    // respects the configured format and level from the start.
    let config = match load_config(Path::new(&cli.config)) {
        Ok(c) => Arc::new(c),
        Err(e) => {
            eprintln!("fatal: failed to load configuration: {e}");
            std::process::exit(1);
        }
    };

    init_logging(&config.observability);

    tracing::info!(
        hostname = %config.server.hostname,
        log_format = %config.observability.log_format,
        log_level = %config.observability.log_level,
        "Sentio SMTP starting"
    );

    // ── Subcommand dispatch ──────────────────────────────────────────────
    match cli.command.unwrap_or(Command::Serve) {
        Command::Migrate => {
            let pg_pool = match sentio_store::pool::PostgresPool::connect(&config.database).await {
                Ok(p) => p,
                Err(e) => {
                    tracing::error!(error = %e, "failed to connect to PostgreSQL");
                    std::process::exit(1);
                }
            };
            match sentio_store::migrate::run_migrations(pg_pool.inner()).await {
                Ok(()) => {
                    tracing::info!("migrations applied");
                    std::process::exit(0);
                }
                Err(e) => {
                    tracing::error!(error = %e, "migration failed");
                    std::process::exit(1);
                }
            }
        }
        Command::Serve => {}
        // Handled above, before configuration is loaded.
        Command::Openapi => unreachable!(),
    }

    // ── Prometheus metrics ───────────────────────────────────────────────
    let _metrics_handle = sentio_observe::install_recorder(&config.observability);
    sentio_observe::register_descriptors();
    tracing::info!("Prometheus metrics recorder installed");

    // ── PostgreSQL ───────────────────────────────────────────────────────
    let pg_pool = match sentio_store::pool::PostgresPool::connect(&config.database).await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "failed to connect to PostgreSQL");
            std::process::exit(1);
        }
    };

    // ── KV backend (per [kv] backend) ─────────────────────────────────────
    let kv = match sentio_store::pool::connect_kv(&config.kv, &config.redis).await {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, backend = %config.kv.backend, "failed to connect to KV backend");
            std::process::exit(1);
        }
    };

    // ── NATS / JetStream ─────────────────────────────────────────────────
    let queue_manager = match sentio_queue::QueueManager::connect(&config.nats).await {
        Ok(q) => q,
        Err(e) => {
            tracing::error!(error = %e, "failed to connect to NATS");
            std::process::exit(1);
        }
    };
    let publisher = match queue_manager.publisher().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "failed to create NATS publisher");
            std::process::exit(1);
        }
    };
    let pipeline_publisher = match queue_manager.publisher().await {
        Ok(p) => p,
        Err(e) => {
            tracing::error!(error = %e, "failed to create pipeline NATS publisher");
            std::process::exit(1);
        }
    };

    // ── S3 blob storage ──────────────────────────────────────────────────
    let blob_store = match sentio_storage::S3BlobStore::connect(&config.storage).await {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to connect to S3 blob store");
            std::process::exit(1);
        }
    };
    let pipeline_blob_store = blob_store.clone();
    tracing::info!(
        endpoint = %config.storage.endpoint_url,
        bucket = %config.storage.bucket,
        "S3 blob store initialized"
    );

    // ── TLS acceptor ─────────────────────────────────────────────────────
    let tls_acceptor = match sentio_smtp_server::build_acceptor(&config.tls) {
        Ok(a) => {
            tracing::info!("TLS acceptor initialized");
            Some(a)
        }
        Err(e) => {
            tracing::warn!(error = %e, "TLS acceptor not available, running without TLS");
            None
        }
    };

    // Captured before the acceptor is moved into the listener below.
    let tls_enabled = tls_acceptor.is_some();

    // ── DNS resolver (for AbuseGuard DNSBL lookups) ──────────────────────
    let resolver = hickory_resolver::TokioResolver::builder_tokio()
        .and_then(|b| b.build())
        .unwrap_or_else(|e| {
            tracing::warn!(error = %e, "failed to load system DNS config, using Google DNS");
            hickory_resolver::TokioResolver::builder_with_config(
                hickory_resolver::config::ResolverConfig::udp_and_tcp(
                    &hickory_resolver::config::GOOGLE,
                ),
                hickory_resolver::net::runtime::TokioRuntimeProvider::default(),
            )
            .build()
            .expect("build Google DNS resolver")
        });

    // ── Restore abuse state from PostgreSQL snapshots ────────────────────
    if let Err(e) =
        sentio_store::abuse_snapshot::restore_from_db(pg_pool.inner(), &kv.clone()).await
    {
        tracing::warn!(error = %e, "failed to restore abuse snapshots from DB (non-fatal)");
    }

    // ── AbuseGuard ───────────────────────────────────────────────────────
    let abuse_guard = Arc::new(sentio_abuse::AbuseGuard::new(
        kv.clone(),
        resolver,
        &config.abuse,
    ));
    tracing::info!("AbuseGuard initialized");

    // ── Shutdown channel ─────────────────────────────────────────────────
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

    // ── SMTP Listener ────────────────────────────────────────────────────
    let smtp_config = sentio_smtp_server::SessionConfig::from_server_config(&config.server);

    // Credential lookup via PgSmtpCredentialRepository
    let cred_repo = Arc::new(sentio_store::postgres::PgSmtpCredentialRepository::new(
        pg_pool.inner().clone(),
    ));
    let credential_lookup: sentio_smtp_server::CredentialLookup =
        Arc::new(move |username: &str| {
            let repo = Arc::clone(&cred_repo);
            let username = username.to_string();
            Box::pin(async move { repo.lookup(&username).await })
        });

    // Auth failure/success callbacks wired to AbuseGuard
    let abuse_for_failure = Arc::clone(&abuse_guard);
    let on_auth_failure: IpCallback = Arc::new(move |ip| {
        let guard = Arc::clone(&abuse_for_failure);
        Box::pin(async move {
            guard.auth.record_failure(&ip).await;
        })
    });

    let abuse_for_success = Arc::clone(&abuse_guard);
    let on_auth_success: IpCallback = Arc::new(move |ip| {
        let guard = Arc::clone(&abuse_for_success);
        Box::pin(async move {
            guard.auth.reset(&ip).await;
        })
    });

    // ── Inbound Pipeline ─────────────────────────────────────────────────
    let dns_resolver_config =
        sentio_auth::DnsResolverConfig::from_config_str(&config.server.dns_resolver);
    tracing::info!(resolver = ?dns_resolver_config, "DNS resolver configured");

    let authenticator = Arc::new(
        sentio_auth::Authenticator::new(dns_resolver_config)
            .expect("failed to create DNS authenticator"),
    );

    let message_repo = sentio_store::postgres::PgMessageRepository::new(pg_pool.inner().clone());
    let event_repo = sentio_store::postgres::PgMessageEventRepository::new(pg_pool.inner().clone());
    let domain_repo = sentio_store::postgres::PgDomainRepository::new(pg_pool.inner().clone());

    // ── ClamAV virus scanner ────────────────────────────────────────────
    let virus_scanner = sentio_storage::ClamAvScanner::new(
        &config.scanning.clamd_host,
        config.scanning.clamd_timeout_secs,
        config.scanning.max_attachment_size_mb,
    );
    tracing::info!(
        host = %config.scanning.clamd_host,
        timeout_secs = config.scanning.clamd_timeout_secs,
        max_attachment_size_mb = config.scanning.max_attachment_size_mb,
        "ClamAV scanner initialized"
    );

    // ── Rspamd spam scorer ────────────────────────────────────────────────
    let spam_scorer = match RspamdScorer::new(&config.spam) {
        Ok(s) => {
            tracing::info!(
                url = %config.spam.rspamd.url,
                timeout_secs = config.spam.rspamd.timeout_secs,
                "rspamd scorer initialized"
            );
            s
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to create rspamd scorer");
            std::process::exit(1);
        }
    };

    let attachment_repo =
        sentio_store::postgres::PgMessageAttachmentRepository::new(pg_pool.inner().clone());
    let mailbox_repo = sentio_store::postgres::PgMailboxRepository::new(pg_pool.inner().clone());

    // Build the VERP codec once and share it between the inbound pipeline
    // (for bounce detection) and the delivery engine (for MAIL FROM rewrite,
    // wired below). Constructed here so InboundPipeline can be created
    // before the delivery engine, but the codec itself is the same.
    let pipeline_verp_codec: Option<Arc<sentio_smtp_client::VerpCodec>> =
        config.server.verp_secret.as_deref().and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(Arc::new(sentio_smtp_client::VerpCodec::new(
                    s.as_bytes().to_vec(),
                )))
            }
        });

    let pipeline = Arc::new(sentio_smtp_server::InboundPipeline::with_verp(
        pipeline_blob_store,
        virus_scanner,
        message_repo,
        event_repo,
        domain_repo,
        pipeline_publisher,
        spam_scorer,
        attachment_repo,
        authenticator,
        mailbox_repo,
        pipeline_verp_codec,
    ));
    tracing::info!("InboundPipeline initialized (virus scanner: ClamAV, spam scorer: rspamd)");

    // ── Outbound Delivery Engine ──────────────────────────────────────────
    let delivery_suppression_repo = Arc::new(sentio_store::postgres::PgSuppressionRepository::new(
        pg_pool.inner().clone(),
    ));
    let delivery_dkim_repo = Arc::new(sentio_store::postgres::PgDkimKeyRepository::new(
        pg_pool.inner().clone(),
    ));
    let delivery_message_repo = Arc::new(sentio_store::postgres::PgMessageRepository::new(
        pg_pool.inner().clone(),
    ));
    let delivery_event_repo = Arc::new(sentio_store::postgres::PgMessageEventRepository::new(
        pg_pool.inner().clone(),
    ));
    let delivery_domain_repo = Arc::new(sentio_store::postgres::PgDomainRepository::new(
        pg_pool.inner().clone(),
    ));
    let delivery_tenant_repo = Arc::new(sentio_store::postgres::PgTenantRepository::new(
        pg_pool.inner().clone(),
    ));
    let delivery_blob_store = Arc::new(blob_store.clone());
    let delivery_authenticator = Arc::new(
        sentio_auth::Authenticator::new(dns_resolver_config)
            .expect("failed to create delivery DNS authenticator"),
    );

    let delivery_pool = Arc::new(sentio_smtp_client::ConnectionPool::new(
        sentio_smtp_client::PoolConfig {
            max_connections: config.delivery.max_connections,
            max_connections_per_dest: config.delivery.max_connections_per_dest,
            idle_timeout: std::time::Duration::from_secs(config.delivery.idle_timeout_secs),
            ..Default::default()
        },
    ));

    let delivery_publisher = match queue_manager.publisher().await {
        Ok(p) => Arc::new(p),
        Err(e) => {
            tracing::error!(error = %e, "failed to create delivery NATS publisher");
            std::process::exit(1);
        }
    };

    // ── IP Warmup Guard ────────────────────────────────────────────────
    let warmup_repo = Arc::new(sentio_store::postgres::PgIpWarmupScheduleRepository::new(
        pg_pool.inner().clone(),
    ));
    let warmup_guard = Arc::new(sentio_smtp_client::WarmupGuard::new(
        warmup_repo.clone(),
        kv.clone(),
    ));

    // ── VERP codec (per-instance) ────────────────────────────────────────
    // Safety: if any tenant has verp_enabled=true but server.verp_secret is
    // unset, refuse to start. Silently falling back to no-VERP would break
    // bounce tracking after a config-roundtrip, which we explicitly want to
    // avoid (the brief calls this out as a hard rule).
    let verp_codec = match config.server.verp_secret.as_deref() {
        Some(secret) if !secret.is_empty() => {
            tracing::info!("VERP codec initialized (server.verp_secret is set)");
            Some(Arc::new(sentio_smtp_client::VerpCodec::new(
                secret.as_bytes().to_vec(),
            )))
        }
        _ => {
            // Probe whether any tenant has VERP enabled - if so, refuse boot.
            let any_verp = match delivery_tenant_repo.list(None, 1000, 0).await {
                Ok(rows) => rows.iter().any(|t| t.verp_enabled),
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "failed to list tenants while probing verp_enabled at boot"
                    );
                    std::process::exit(1);
                }
            };
            if any_verp {
                tracing::error!(
                    "server.verp_secret is unset but one or more tenants have verp_enabled=true; \
                     refusing to start - either set [server] verp_secret in the config or set \
                     verp_enabled=false on all tenants"
                );
                std::process::exit(1);
            }
            tracing::info!("VERP disabled (server.verp_secret unset, no tenant opts in)");
            None
        }
    };

    let delivery_engine = sentio_smtp_client::DeliveryEngine::new(
        delivery_blob_store,
        delivery_message_repo,
        delivery_event_repo,
        delivery_suppression_repo,
        delivery_dkim_repo,
        delivery_domain_repo,
        delivery_tenant_repo,
        delivery_authenticator,
        delivery_pool,
        delivery_publisher,
        config.delivery.clone(),
        config.server.hostname.clone(),
        config.auth.dane_enabled,
        config.auth.arc_sign_forward,
        Some(warmup_guard.clone()),
        verp_codec,
    );

    let delivery_consumer = match queue_manager
        .consumer_on(
            sentio_queue::STREAM_SUBMIT,
            "delivery",
            sentio_queue::FILTER_OUTBOUND_ALL,
            config.nats.prefetch_count,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to create delivery consumer");
            std::process::exit(1);
        }
    };
    let delivery_handle = match delivery_consumer.run(delivery_engine).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "failed to start delivery consumer");
            std::process::exit(1);
        }
    };
    tracing::info!(
        "DeliveryEngine consumer started on stream {} (filter {})",
        sentio_queue::STREAM_SUBMIT,
        sentio_queue::FILTER_OUTBOUND_ALL
    );

    // ── LLM Backend ──────────────────────────────────────────────────────
    let llm_backend = Arc::new(sentio_llm::create_backend(&config.llm).unwrap_or_else(|e| {
        tracing::warn!(error = %e, "failed to create LLM backend, using noop");
        sentio_llm::LlmBackend::Noop(sentio_llm::NoopLlmProvider)
    }));
    tracing::info!(provider = %config.llm.provider, enabled = config.llm.enabled, "LLM backend initialized");

    // ── Inbound Routing Consumer ────────────────────────────────────────
    let inbound_route_repo = Arc::new(sentio_store::postgres::PgInboundRouteRepository::new(
        pg_pool.inner().clone(),
    ));
    let inbound_event_repo = Arc::new(sentio_store::postgres::PgMessageEventRepository::new(
        pg_pool.inner().clone(),
    ));
    let inbound_blob_store = Arc::new(blob_store.clone());
    let inbound_message_repo = Arc::new(sentio_store::postgres::PgMessageRepository::new(
        pg_pool.inner().clone(),
    ));
    let inbound_delivery_log_repo = Arc::new(
        sentio_store::postgres::PgInboundRouteDeliveryLogRepository::new(pg_pool.inner().clone()),
    );
    let inbound_engine = sentio_smtp_server::InboundEngine::new(
        inbound_route_repo,
        inbound_event_repo,
        inbound_blob_store,
        inbound_message_repo,
        inbound_delivery_log_repo,
        llm_backend,
        Arc::new(config.llm.clone()),
    );

    let inbound_consumer = match queue_manager
        .consumer_on(
            sentio_queue::STREAM_SUBMIT,
            "inbound-routing",
            sentio_queue::FILTER_INBOUND_ALL,
            config.nats.prefetch_count,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to create inbound routing consumer");
            std::process::exit(1);
        }
    };
    let inbound_handle = match inbound_consumer.run(inbound_engine).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "failed to start inbound routing consumer");
            std::process::exit(1);
        }
    };
    tracing::info!(
        "InboundEngine consumer started on stream {} (filter {})",
        sentio_queue::STREAM_SUBMIT,
        sentio_queue::FILTER_INBOUND_ALL
    );

    // ── Webhook Event Consumer ──────────────────────────────────────────
    let webhook_repo = Arc::new(sentio_store::postgres::PgWebhookRepository::new(
        pg_pool.inner().clone(),
    ));
    let webhook_log_repo = Arc::new(sentio_store::postgres::PgWebhookDeliveryLogRepository::new(
        pg_pool.inner().clone(),
    ));
    let webhook_sender = sentio_webhooks::ReqwestSender::new(config.webhooks.delivery_timeout_secs);
    let webhook_dispatcher = Arc::new(sentio_webhooks::WebhookDispatcher::new(
        webhook_sender,
        webhook_repo,
        webhook_log_repo,
    ));
    let webhook_handler = sentio_webhooks::WebhookEventHandler::new(webhook_dispatcher);

    let webhook_consumer = match queue_manager
        .consumer_on(
            sentio_queue::STREAM_EVENTS,
            "webhook",
            sentio_queue::FILTER_EVENTS_ALL,
            config.nats.prefetch_count,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to create webhook event consumer");
            std::process::exit(1);
        }
    };
    let webhook_handle = match webhook_consumer.run(webhook_handler).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "failed to start webhook event consumer");
            std::process::exit(1);
        }
    };
    tracing::info!(
        "WebhookEventHandler consumer started on stream {} (filter {})",
        sentio_queue::STREAM_EVENTS,
        sentio_queue::FILTER_EVENTS_ALL
    );

    // ── Analytics Event Consumer ────────────────────────────────────────
    let analytics_handler = sentio_api::analytics_consumer::AnalyticsEventHandler::new();

    let analytics_consumer = match queue_manager
        .consumer_on(
            sentio_queue::STREAM_EVENTS,
            "analytics",
            sentio_queue::FILTER_EVENTS_ALL,
            config.nats.prefetch_count,
        )
        .await
    {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, "failed to create analytics event consumer");
            std::process::exit(1);
        }
    };
    let analytics_handle = match analytics_consumer.run(analytics_handler).await {
        Ok(h) => h,
        Err(e) => {
            tracing::error!(error = %e, "failed to start analytics event consumer");
            std::process::exit(1);
        }
    };
    tracing::info!(
        "AnalyticsEventHandler consumer started on stream {} (filter {})",
        sentio_queue::STREAM_EVENTS,
        sentio_queue::FILTER_EVENTS_ALL
    );

    // ── Listmonk Bounce Bridge ──────────────────────────────────────────
    // Conditional: only starts when [listmonk] is enabled in config. A
    // dedicated durable consumer on sentio.events.event.bounce so it
    // doesn't see delivery / open / click / etc. events.
    // Held in scope but not joined at shutdown drain - JetStream
    // redelivers any in-flight bounce events on next startup, so an
    // unclean exit here is safe.
    let _listmonk_handle = if config.listmonk.enabled {
        if config.listmonk.url.is_empty()
            || config.listmonk.username.is_empty()
            || config.listmonk.password.is_empty()
        {
            tracing::warn!(
                "listmonk bridge enabled but url/username/password missing - not starting"
            );
            None
        } else {
            let listmonk_url_for_log = config.listmonk.url.clone();
            let bridge =
                sentio_smtp_server::listmonk_bridge::ListmonkBridge::new(config.listmonk.clone());
            const LISTMONK_BOUNCE_SUBJECT: &str = "sentio.events.event.bounce";
            let consumer = match queue_manager
                .consumer_on(
                    sentio_queue::STREAM_EVENTS,
                    "listmonk-bridge",
                    LISTMONK_BOUNCE_SUBJECT,
                    config.nats.prefetch_count,
                )
                .await
            {
                Ok(c) => c,
                Err(e) => {
                    tracing::error!(error = %e, "failed to create listmonk bridge consumer");
                    std::process::exit(1);
                }
            };
            let handle = match consumer.run(bridge).await {
                Ok(h) => h,
                Err(e) => {
                    tracing::error!(error = %e, "failed to start listmonk bridge consumer");
                    std::process::exit(1);
                }
            };
            tracing::info!(
                url = %listmonk_url_for_log,
                "Listmonk bounce bridge started on stream {} (filter {})",
                sentio_queue::STREAM_EVENTS,
                LISTMONK_BOUNCE_SUBJECT
            );
            Some(handle)
        }
    } else {
        None
    };

    // NOTE: With JetStream we no longer need a dedicated retry-requeue
    // consumer. `HandlerResult::Retry` is translated to
    // `AckKind::Nak(Some(delay))`, which lets the server redeliver the same
    // message after the requested delay - the entire `sentio.retry.wait` +
    // `sentio.retry.requeue` flow has been removed.

    // Sender domain enforcement callback for submission/SMTPS ports
    let pool_for_domain_check = pg_pool.inner().clone();
    let domain_check: sentio_smtp_server::DomainCheck = Arc::new(move |tenant_id, domain_name| {
        let repo = sentio_store::postgres::PgDomainRepository::new(pool_for_domain_check.clone());
        Box::pin(async move {
            let record = repo.get_by_name(tenant_id, &domain_name).await?;
            if record.status != DomainStatus::Verified {
                return Err(SentioError::Validation("domain not active".into()));
            }
            if !record.use_for_sending {
                return Err(SentioError::Validation(
                    "domain not enabled for sending".into(),
                ));
            }
            Ok(())
        })
    });

    let session_deps = sentio_smtp_server::SessionDeps {
        credential_lookup,
        on_auth_failure,
        on_auth_success,
        message_processor: Some(pipeline.into_processor()),
        domain_check: Some(domain_check),
    };

    // Connection check callback wired to AbuseGuard
    let abuse_for_check = Arc::clone(&abuse_guard);
    let connection_check: ConnectionCheck = Arc::new(move |ip| {
        let guard = Arc::clone(&abuse_for_check);
        Box::pin(async move { guard.check_connection(&ip).await.map_err(|_| ()) })
    });

    let smtp_listener = sentio_smtp_server::SmtpListener::new(
        smtp_config,
        tls_acceptor,
        config.server.proxy_protocol,
        session_deps,
        connection_check,
        config.server.max_connections,
    );

    let smtp_addrs = config.server.listen_smtp.clone();
    let smtps_addrs = config.server.listen_smtps.clone();
    let submission_addrs = config.server.listen_submission.clone();
    let smtp_shutdown_rx = shutdown_rx.clone();

    let smtp_handle = tokio::spawn(async move {
        if let Err(e) = smtp_listener
            .run(
                &smtp_addrs,
                &smtps_addrs,
                &submission_addrs,
                smtp_shutdown_rx,
            )
            .await
        {
            tracing::error!(error = %e, "SMTP listener failed");
        }
    });

    // ── API Server ───────────────────────────────────────────────────────
    let api_state = sentio_api::AppState::new(
        pg_pool.inner().clone(),
        publisher,
        blob_store,
        (*config).clone(),
    )
    .with_kv(kv.clone());

    let api_shutdown_rx = shutdown_rx.clone();
    let api_handle = tokio::spawn(async move {
        if let Err(e) = sentio_api::start(api_state, api_shutdown_rx).await {
            tracing::error!(error = %e, "API server failed");
        }
    });

    // ── Background partition manager ─────────────────────────────────────
    // Creates month partitions for messages/message_events/engagement_events/
    // message_attachments so the schema's bootstrap window does not expire.
    // Runs once at startup, then daily.
    let partitions_pool = pg_pool.inner().clone();
    let mut partitions_shutdown = shutdown_rx.clone();
    match sentio_store::partitions::ensure_future_partitions(&partitions_pool, 2).await {
        Ok(n) if n > 0 => tracing::info!(created = n, "created month partitions at startup"),
        Ok(_) => tracing::debug!("partition manager: no new partitions needed"),
        Err(e) => tracing::error!(error = %e, "partition manager failed at startup"),
    }
    let partitions_handle = tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(24 * 3600); // daily
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    match sentio_store::partitions::ensure_future_partitions(&partitions_pool, 2).await {
                        Ok(n) if n > 0 => tracing::info!(created = n, "created month partitions"),
                        Ok(_) => tracing::debug!("partition manager: no new partitions needed"),
                        Err(e) => tracing::warn!(error = %e, "partition manager run failed"),
                    }
                }
                _ = partitions_shutdown.changed() => {
                    tracing::debug!("partition manager task shutting down");
                    break;
                }
            }
        }
    });

    // ── Background abuse snapshot task ───────────────────────────────────
    let snapshot_pool = pg_pool.inner().clone();
    let snapshot_kv = kv.clone();
    let mut snapshot_shutdown = shutdown_rx.clone();
    let snapshot_handle = tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(300); // 5 minutes
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    if let Err(e) = sentio_store::abuse_snapshot::snapshot_to_db(
                        &snapshot_pool,
                        &snapshot_kv,
                    ).await {
                        tracing::warn!(error = %e, "abuse snapshot failed");
                    }
                }
                _ = snapshot_shutdown.changed() => {
                    tracing::debug!("abuse snapshot task shutting down");
                    break;
                }
            }
        }
    });

    // ── Background warmup advance task ────────────────────────────────
    let warmup_guard_bg = warmup_guard.clone();
    let mut warmup_shutdown = shutdown_rx.clone();
    let warmup_handle = tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(6 * 3600); // every 6 hours
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    if let Err(e) = warmup_guard_bg.advance_daily_schedules().await {
                        tracing::warn!(error = %e, "warmup schedule advance failed");
                    }
                }
                _ = warmup_shutdown.changed() => {
                    tracing::debug!("warmup advance task shutting down");
                    break;
                }
            }
        }
    });

    // ── Background error event retention cleanup ──────────────────────
    let retention_pool = pg_pool.inner().clone();
    let retention_days = config.error_events.retention_days;
    let mut retention_shutdown = shutdown_rx.clone();
    let retention_handle = tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(6 * 3600); // every 6 hours
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    let cutoff = chrono::Utc::now()
                        - chrono::Duration::days(i64::from(retention_days));
                    let repo = sentio_store::postgres::PgErrorEventRepository::new(
                        retention_pool.clone(),
                    );
                    match sentio_core::traits::ErrorEventRepository::delete_before(&repo, cutoff).await {
                        Ok(deleted) if deleted > 0 => {
                            tracing::info!(deleted, "cleaned up old error events");
                        }
                        Ok(_) => {}
                        Err(e) => {
                            tracing::warn!(error = %e, "error event retention cleanup failed");
                        }
                    }
                }
                _ = retention_shutdown.changed() => {
                    tracing::debug!("error event retention task shutting down");
                    break;
                }
            }
        }
    });

    // ── Background DNS verification sweep ─────────────────────────────
    let dns_check_pool = pg_pool.inner().clone();
    let dns_check_hostname = config.server.hostname.clone();
    let dns_check_interval_hours = config.deliverability.dns_check_interval_hours.max(1);
    let mut dns_check_shutdown = shutdown_rx.clone();
    let dns_check_handle = tokio::spawn(async move {
        let interval = std::time::Duration::from_secs(u64::from(dns_check_interval_hours) * 3600);
        loop {
            tokio::select! {
                _ = tokio::time::sleep(interval) => {
                    let domain_repo = sentio_store::postgres::PgDomainRepository::new(
                        dns_check_pool.clone(),
                    );
                    let dkim_repo = sentio_store::postgres::PgDkimKeyRepository::new(
                        dns_check_pool.clone(),
                    );
                    let tenant_repo = sentio_store::postgres::PgTenantRepository::new(
                        dns_check_pool.clone(),
                    );
                    let checker = match sentio_auth::DnsChecker::new(dns_check_hostname.clone()) {
                        Ok(c) => c,
                        Err(e) => {
                            tracing::warn!(error = %e, "dns checker init failed");
                            continue;
                        }
                    };
                    match sentio_core::traits::DomainRepository::list_verified(&domain_repo).await {
                        Ok(domains) => {
                            let total = domains.len();
                            for d in domains {
                                // VERP opt-in flag is per-tenant; the
                                // return-path subcheck is skipped when off
                                // so it never sits at NotApplicable for
                                // tenants who aren't using bounce.{domain}.
                                let verp_enabled =
                                    sentio_core::traits::TenantRepository::get(
                                        &tenant_repo,
                                        d.tenant_id,
                                    )
                                    .await
                                    .map(|t| t.verp_enabled)
                                    .unwrap_or(false);
                                let outcome = checker.check(&d, &dkim_repo, verp_enabled).await;
                                let update = sentio_core::traits::DnsCheckUpdate {
                                    spf_status: outcome.spf.0,
                                    spf_error: outcome.spf.1,
                                    dkim_status: outcome.dkim.0,
                                    dkim_error: outcome.dkim.1,
                                    dmarc_status: outcome.dmarc.0,
                                    dmarc_error: outcome.dmarc.1,
                                    mx_status: outcome.mx.0,
                                    mx_error: outcome.mx.1,
                                    return_path_status: outcome.return_path.0,
                                    return_path_error: outcome.return_path.1,
                                };
                                if let Err(e) =
                                    sentio_core::traits::DomainRepository::update_dns_checks(
                                        &domain_repo,
                                        d.id,
                                        update,
                                    )
                                    .await
                                {
                                    tracing::warn!(
                                        error = %e,
                                        domain = %d.domain_name,
                                        "dns check sweep: persist failed",
                                    );
                                }
                            }
                            tracing::debug!(total, "dns check sweep complete");
                        }
                        Err(e) => tracing::warn!(error = %e, "dns check sweep: list_verified failed"),
                    }
                }
                _ = dns_check_shutdown.changed() => {
                    tracing::debug!("dns check sweep task shutting down");
                    break;
                }
            }
        }
    });

    print_startup_banner(&config, tls_enabled);
    tracing::info!("Sentio SMTP ready");

    // ── Wait for shutdown signal ─────────────────────────────────────────
    #[cfg(unix)]
    {
        let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    }

    tracing::info!("shutdown signal received, draining connections");
    let _ = shutdown_tx.send(true);

    // Wait for tasks to finish with a drain timeout
    let drain_secs = config.server.shutdown_drain_secs;
    let drain_timeout = std::time::Duration::from_secs(drain_secs);

    let drain_result = tokio::time::timeout(drain_timeout, async {
        let _ = tokio::join!(
            smtp_handle,
            api_handle,
            delivery_handle,
            inbound_handle,
            webhook_handle,
            analytics_handle,
            snapshot_handle,
            warmup_handle,
            retention_handle,
            dns_check_handle,
            partitions_handle
        );
    })
    .await;

    if drain_result.is_err() {
        tracing::warn!(drain_secs, "shutdown drain timeout exceeded, forcing exit");
    }

    tracing::info!("Sentio SMTP stopped");
}
/// Print a startup banner summarising what is listening and what it connected
/// to.
///
/// Skipped when logs are JSON: a decorative banner in the middle of a stream
/// that a log shipper is parsing line by line is not decorative, it is a parse
/// error. Colour is emitted only for a terminal, so redirecting to a file does
/// not fill it with escape sequences.
fn print_startup_banner(config: &sentio_core::config::SentioConfig, tls_enabled: bool) {
    use std::io::IsTerminal;

    if config.observability.log_format.eq_ignore_ascii_case("json") {
        return;
    }

    let tty = std::io::stdout().is_terminal();
    let (cyan, dim, reset) = if tty {
        ("\x1b[36m", "\x1b[2m", "\x1b[0m")
    } else {
        ("", "", "")
    };

    let join = |addrs: &[String]| -> String {
        if addrs.is_empty() {
            "disabled".to_string()
        } else {
            addrs.join(", ")
        }
    };

    let row = |label: &str, value: &str| {
        println!("  {dim}{label:<11}{reset}{value}");
    };

    println!();
    println!(
        "  {cyan}▄▀▀ █▀▀ █▄ █ ▀█▀ █ ▄▀▄{reset}   {dim}v{}{reset}",
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "  {cyan}▀▀▄ █▀▀ █ ▀█  █  █ █ █{reset}   {dim}{}{reset}",
        config.server.hostname
    );
    println!("  {cyan}▀▀▀ ▀▀▀ ▀  ▀  ▀  ▀ ▀▀▀{reset}");
    println!();

    row("SMTP", &join(&config.server.listen_smtp));
    row("Submission", &join(&config.server.listen_submission));
    if tls_enabled {
        row("SMTPS", &join(&config.server.listen_smtps));
    } else {
        row("SMTPS", "disabled (no TLS certificate)");
    }
    row("API", &format!("http://{}", config.server.listen_api));
    row(
        "Reference",
        &format!("http://{}/docs", config.server.listen_api),
    );
    println!();

    row("Database", &redact_url(&config.database.url));
    row("KV", &config.kv.backend);
    row("Queue", &redact_url(&config.nats.url));
    row(
        "Storage",
        &format!(
            "{} ({})",
            config.storage.bucket,
            redact_url(&config.storage.endpoint_url)
        ),
    );
    row(
        "Antivirus",
        if config.scanning.enabled {
            &config.scanning.clamd_host
        } else {
            "disabled"
        },
    );
    row("Spam", &config.spam.backend);
    row(
        "LLM",
        &if config.llm.enabled {
            format!("{} ({})", config.llm.provider, config.llm.model)
        } else {
            "disabled".to_string()
        },
    );
    println!();
}

/// Strip any `user:password@` from a URL before it is displayed.
///
/// Connection strings routinely carry credentials, and a startup banner is
/// exactly the sort of output that ends up pasted into an issue.
fn redact_url(url: &str) -> String {
    let (scheme, rest) = match url.split_once("://") {
        Some((s, r)) => (format!("{s}://"), r),
        None => (String::new(), url),
    };
    // rsplit, not split: a password containing a literal '@' would otherwise
    // leave its tail in the output.
    match rest.rsplit_once('@') {
        Some((_creds, host)) => format!("{scheme}{host}"),
        None => format!("{scheme}{rest}"),
    }
}

#[cfg(test)]
mod banner_tests {
    use super::redact_url;

    #[test]
    fn strips_credentials() {
        assert_eq!(
            redact_url("postgres://user:secret@db.internal:5432/sentio"),
            "postgres://db.internal:5432/sentio"
        );
        assert_eq!(
            redact_url("nats://nats:4222"),
            "nats://nats:4222",
            "no credentials means nothing to strip"
        );
        assert_eq!(redact_url("http://minio:9000"), "http://minio:9000");
    }

    #[test]
    fn strips_password_containing_an_at_sign() {
        assert_eq!(
            redact_url("postgres://user:p@ss@db:5432/x"),
            "postgres://db:5432/x"
        );
    }

    #[test]
    fn handles_a_url_without_a_scheme() {
        assert_eq!(redact_url("localhost:6379"), "localhost:6379");
        assert_eq!(redact_url("user:pw@localhost:6379"), "localhost:6379");
    }
}
