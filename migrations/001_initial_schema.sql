-- =============================================================================
-- Sentio SMTP - initial schema
-- =============================================================================
-- Squashed from the incremental migration history at the point this repository
-- was opened. It is the schema those migrations converged on, not a replay of
-- them, so renamed columns and reworked indexes appear only in final form.
--
-- Partitions are deliberately NOT baked in. The four monthly-partitioned
-- tables (messages, message_events, engagement_events, message_attachments)
-- get their partitions from the DO block at the end, relative to the install
-- date, and from sentio_create_month_partitions() thereafter. Dumping the
-- partitions that existed when this file was generated would hand every future
-- install a set of stale months and none for the current one.
--
-- No BEGIN/COMMIT: sqlx already runs each migration inside a transaction, and
-- nesting one produces "there is already a transaction in progress" warnings.
-- =============================================================================

--
-- Name: sentio_create_month_partitions(integer); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.sentio_create_month_partitions(months_ahead integer DEFAULT 2) RETURNS integer
    LANGUAGE plpgsql SECURITY DEFINER
    SET "TimeZone" TO 'UTC'
    SET search_path TO 'public', 'pg_temp'
    AS $$
DECLARE
    month_start DATE;
    month_end   DATE;
    part_suffix TEXT;
    tbl         TEXT;
    part_name   TEXT;
    created     INT := 0;
BEGIN
    IF months_ahead < 0 OR months_ahead > 24 THEN
        RAISE EXCEPTION 'months_ahead out of range: %', months_ahead;
    END IF;

    FOR i IN 0..months_ahead LOOP
        month_start := date_trunc('month', CURRENT_DATE + (i || ' months')::INTERVAL)::DATE;
        month_end   := (month_start + INTERVAL '1 month')::DATE;
        part_suffix := to_char(month_start, 'YYYY_MM');

        FOREACH tbl IN ARRAY ARRAY['messages','message_events','engagement_events','message_attachments']
        LOOP
            part_name := tbl || '_' || part_suffix;
            IF NOT EXISTS (
                SELECT 1 FROM pg_class c
                JOIN pg_namespace n ON n.oid = c.relnamespace
                WHERE c.relname = part_name AND n.nspname = 'public'
            ) THEN
                EXECUTE format(
                    'CREATE TABLE %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                    part_name, tbl, month_start, month_end
                );
                created := created + 1;
            END IF;
        END LOOP;
    END LOOP;

    RETURN created;
END;
$$;

--
-- Name: set_updated_at(); Type: FUNCTION; Schema: public; Owner: -
--

CREATE FUNCTION public.set_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

--
-- Name: abuse_snapshots; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.abuse_snapshots (
    ip inet NOT NULL,
    snapshot_type text NOT NULL,
    value text NOT NULL,
    expires_at timestamp with time zone,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT abuse_snapshots_snapshot_type_check CHECK ((snapshot_type = ANY (ARRAY['ban'::text, 'reputation'::text, 'whitelist'::text])))
);

--
-- Name: api_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.api_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    key_hash text NOT NULL,
    key_prefix text NOT NULL,
    name text NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    last_used timestamp with time zone,
    expires_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: dkim_keys; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dkim_keys (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    domain_id uuid NOT NULL,
    selector text NOT NULL,
    algorithm text DEFAULT 'ed25519'::text NOT NULL,
    private_key text NOT NULL,
    public_key text NOT NULL,
    key_size integer,
    status text DEFAULT 'active'::text NOT NULL,
    activated_at timestamp with time zone,
    retired_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT dkim_keys_algorithm_check CHECK ((algorithm = ANY (ARRAY['ed25519'::text, 'rsa'::text]))),
    CONSTRAINT dkim_keys_status_check CHECK ((status = ANY (ARRAY['active'::text, 'rotating'::text, 'retired'::text])))
);

--
-- Name: dmarc_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.dmarc_reports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    direction text NOT NULL,
    report_id text NOT NULL,
    org_name text,
    date_begin timestamp with time zone NOT NULL,
    date_end timestamp with time zone NOT NULL,
    source_ip inet,
    report_xml text,
    total_count integer DEFAULT 0 NOT NULL,
    dkim_pass integer DEFAULT 0 NOT NULL,
    dkim_fail integer DEFAULT 0 NOT NULL,
    spf_pass integer DEFAULT 0 NOT NULL,
    spf_fail integer DEFAULT 0 NOT NULL,
    dmarc_pass integer DEFAULT 0 NOT NULL,
    dmarc_fail integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT dmarc_reports_direction_check CHECK ((direction = ANY (ARRAY['inbound'::text, 'outbound'::text])))
);

--
-- Name: domains; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.domains (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    domain_name text NOT NULL,
    use_for_sending boolean DEFAULT true NOT NULL,
    use_for_receiving boolean DEFAULT false NOT NULL,
    status text DEFAULT 'pending'::text NOT NULL,
    spf_status text DEFAULT 'pending'::text NOT NULL,
    spf_error text,
    dkim_status text DEFAULT 'pending'::text NOT NULL,
    dkim_error text,
    dmarc_status text DEFAULT 'pending'::text NOT NULL,
    dmarc_error text,
    mx_status text DEFAULT 'pending'::text NOT NULL,
    mx_error text,
    return_path_status text DEFAULT 'pending'::text NOT NULL,
    return_path_error text,
    dns_checked_at timestamp with time zone,
    verification_token text NOT NULL,
    verified_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    reject_unknown_recipients boolean DEFAULT false NOT NULL,
    CONSTRAINT domains_dkim_status_check CHECK ((dkim_status = ANY (ARRAY['pending'::text, 'verified'::text, 'failed'::text]))),
    CONSTRAINT domains_dmarc_status_check CHECK ((dmarc_status = ANY (ARRAY['pending'::text, 'verified'::text, 'failed'::text]))),
    CONSTRAINT domains_mx_status_check CHECK ((mx_status = ANY (ARRAY['pending'::text, 'verified'::text, 'failed'::text, 'not_applicable'::text]))),
    CONSTRAINT domains_return_path_status_check CHECK ((return_path_status = ANY (ARRAY['pending'::text, 'verified'::text, 'failed'::text, 'not_applicable'::text]))),
    CONSTRAINT domains_spf_status_check CHECK ((spf_status = ANY (ARRAY['pending'::text, 'verified'::text, 'failed'::text]))),
    CONSTRAINT domains_status_check CHECK ((status = ANY (ARRAY['pending'::text, 'verified'::text, 'failed'::text])))
);

--
-- Name: engagement_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.engagement_events (
    id uuid DEFAULT uuidv7() NOT NULL,
    message_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    event_type text NOT NULL,
    ip_address inet,
    user_agent text,
    url text,
    referer text,
    client_name text,
    client_version text,
    device_type text,
    os_name text,
    os_version text,
    is_bot boolean DEFAULT false NOT NULL,
    proxy_open boolean DEFAULT false NOT NULL,
    country_code character(2),
    region text,
    city text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT engagement_events_device_type_check CHECK (((device_type IS NULL) OR (device_type = ANY (ARRAY['desktop'::text, 'mobile'::text, 'tablet'::text, 'unknown'::text])))),
    CONSTRAINT engagement_events_event_type_check CHECK ((event_type = ANY (ARRAY['opened'::text, 'clicked'::text, 'unsubscribed'::text])))
)
PARTITION BY RANGE (created_at);

--
-- Name: error_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.error_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    severity text NOT NULL,
    component text NOT NULL,
    error_type text NOT NULL,
    message text NOT NULL,
    stack_trace text,
    message_id uuid,
    request_id text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT error_events_component_check CHECK ((component = ANY (ARRAY['smtp_server'::text, 'smtp_client'::text, 'queue'::text, 'api'::text, 'webhooks'::text, 'auth'::text, 'abuse'::text, 'storage'::text, 'spam'::text, 'llm'::text]))),
    CONSTRAINT error_events_error_type_check CHECK ((error_type = ANY (ARRAY['database'::text, 'redis'::text, 'queue'::text, 'storage'::text, 'smtp'::text, 'auth'::text, 'rate_limit'::text, 'not_found'::text, 'validation'::text, 'internal'::text, 'config'::text]))),
    CONSTRAINT error_events_severity_check CHECK ((severity = ANY (ARRAY['warning'::text, 'error'::text, 'critical'::text])))
);

--
-- Name: fbl_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.fbl_reports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    original_message_id uuid,
    original_message_id_hdr text,
    complained_recipient text NOT NULL,
    complaint_type text DEFAULT 'abuse'::text NOT NULL,
    feedback_type text,
    source_ip inet,
    arrival_date timestamp with time zone,
    report_raw text,
    auto_suppressed boolean DEFAULT false NOT NULL,
    processed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT fbl_reports_complaint_type_check CHECK ((complaint_type = ANY (ARRAY['abuse'::text, 'fraud'::text, 'virus'::text, 'other'::text, 'not-spam'::text])))
);

--
-- Name: inbound_route_delivery_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.inbound_route_delivery_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    inbound_route_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    message_id uuid,
    recipient text NOT NULL,
    http_status integer,
    response_body text,
    attempt_number integer NOT NULL,
    delivered_at timestamp with time zone,
    failed_at timestamp with time zone,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: inbound_routes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.inbound_routes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    pattern text NOT NULL,
    match_type text DEFAULT 'exact'::text NOT NULL,
    webhook_url text NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    llm_classify boolean DEFAULT false NOT NULL,
    auto_respond boolean DEFAULT false NOT NULL,
    auto_respond_config jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT inbound_routes_match_type_check CHECK ((match_type = ANY (ARRAY['exact'::text, 'regex'::text, 'domain'::text, 'catch_all'::text])))
);

--
-- Name: ip_pools; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ip_pools (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    pool_type text DEFAULT 'shared'::text NOT NULL,
    ips inet[] NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ip_pools_pool_type_check CHECK ((pool_type = ANY (ARRAY['shared'::text, 'dedicated'::text]))),
    CONSTRAINT ip_pools_status_check CHECK ((status = ANY (ARRAY['active'::text, 'draining'::text, 'inactive'::text])))
);

--
-- Name: ip_warmup_schedules; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.ip_warmup_schedules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ip_pool_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    start_date date NOT NULL,
    current_day integer DEFAULT 0 NOT NULL,
    daily_limit integer DEFAULT 100 NOT NULL,
    daily_increase_pct numeric(5,2) DEFAULT 25.00 NOT NULL,
    max_daily_limit integer DEFAULT 100000 NOT NULL,
    isp_overrides jsonb DEFAULT '{}'::jsonb,
    status text DEFAULT 'scheduled'::text NOT NULL,
    completed_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT ip_warmup_schedules_status_check CHECK ((status = ANY (ARRAY['scheduled'::text, 'in_progress'::text, 'paused'::text, 'completed'::text])))
);

--
-- Name: mailboxes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.mailboxes (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    domain_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    address text NOT NULL,
    display_name text,
    status text DEFAULT 'active'::text NOT NULL,
    forward_to text[],
    auto_reply boolean DEFAULT false NOT NULL,
    auto_reply_subject text,
    auto_reply_body text,
    metadata jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT mailboxes_status_check CHECK ((status = ANY (ARRAY['active'::text, 'disabled'::text])))
);

--
-- Name: message_attachments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_attachments (
    id uuid DEFAULT uuidv7() NOT NULL,
    message_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    filename text NOT NULL,
    content_type text NOT NULL,
    size bigint NOT NULL,
    content_id text,
    disposition text DEFAULT 'attachment'::text NOT NULL,
    blob_key character varying(512) CONSTRAINT message_attachments_seaweedfs_fid_not_null NOT NULL,
    checksum_sha256 text,
    scan_status text DEFAULT 'pending'::text NOT NULL,
    scan_result text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT message_attachments_disposition_check CHECK ((disposition = ANY (ARRAY['attachment'::text, 'inline'::text]))),
    CONSTRAINT message_attachments_scan_status_check CHECK ((scan_status = ANY (ARRAY['pending'::text, 'clean'::text, 'infected'::text, 'error'::text])))
)
PARTITION BY RANGE (created_at);

--
-- Name: message_events; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.message_events (
    id uuid DEFAULT uuidv7() NOT NULL,
    message_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    event_type text NOT NULL,
    smtp_response text,
    remote_mta text,
    diagnostic_code text,
    bounce_class text,
    retry_count integer,
    next_retry_at timestamp with time zone,
    source_ip inet,
    destination_ip inet,
    tls_version text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT message_events_bounce_class_check CHECK (((bounce_class IS NULL) OR (bounce_class = ANY (ARRAY['hard'::text, 'soft'::text, 'block'::text])))),
    CONSTRAINT message_events_event_type_check CHECK ((event_type = ANY (ARRAY['queued'::text, 'processed'::text, 'delivered'::text, 'deferred'::text, 'bounced'::text, 'dropped'::text, 'held'::text, 'released'::text])))
)
PARTITION BY RANGE (created_at);

--
-- Name: messages; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.messages (
    id uuid DEFAULT uuidv7() NOT NULL,
    tenant_id uuid NOT NULL,
    domain_id uuid,
    direction text DEFAULT 'outbound'::text NOT NULL,
    envelope_from text NOT NULL,
    envelope_to text[] NOT NULL,
    header_from text,
    header_to text[] DEFAULT '{}'::text[],
    header_cc text[] DEFAULT '{}'::text[],
    header_reply_to text,
    subject text,
    message_id_header text,
    status text DEFAULT 'queued'::text NOT NULL,
    tags text[] DEFAULT '{}'::text[],
    metadata jsonb DEFAULT '{}'::jsonb,
    message_size bigint,
    raw_eml_key character varying(512),
    spam_score double precision,
    spam_action text,
    send_at timestamp with time zone,
    dsn_ret text,
    dsn_envid text,
    dsn_notify jsonb DEFAULT '{}'::jsonb NOT NULL,
    dsn_orcpt jsonb DEFAULT '{}'::jsonb NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    delivered_at timestamp with time zone,
    bounced_at timestamp with time zone,
    llm_category text,
    llm_summary text,
    llm_classified_at timestamp with time zone,
    bounce_class text,
    smtp_code integer,
    enhanced_status text,
    diagnostic text,
    failed_recipient text,
    CONSTRAINT messages_bounce_class_check CHECK (((bounce_class IS NULL) OR (bounce_class = ANY (ARRAY['hard'::text, 'soft'::text, 'block'::text])))),
    CONSTRAINT messages_direction_check CHECK ((direction = ANY (ARRAY['inbound'::text, 'outbound'::text]))),
    CONSTRAINT messages_dsn_ret_check CHECK (((dsn_ret IS NULL) OR (dsn_ret = ANY (ARRAY['FULL'::text, 'HDRS'::text])))),
    CONSTRAINT messages_llm_category_check CHECK (((llm_category IS NULL) OR (llm_category = ANY (ARRAY['conversation'::text, 'transactional'::text, 'marketing'::text, 'billing'::text, 'notification'::text, 'support'::text, 'spam'::text, 'threat'::text, 'other'::text])))),
    CONSTRAINT messages_status_check CHECK ((status = ANY (ARRAY['queued'::text, 'processing'::text, 'delivered'::text, 'deferred'::text, 'bounced'::text, 'dropped'::text, 'scheduled'::text, 'held'::text])))
)
PARTITION BY RANGE (created_at);

--
-- Name: oauth_authorization_codes; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_authorization_codes (
    code text NOT NULL,
    client_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    redirect_uri text NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    code_challenge text,
    code_challenge_method text,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_authorization_codes_code_challenge_method_check CHECK (((code_challenge_method IS NULL) OR (code_challenge_method = ANY (ARRAY['S256'::text, 'plain'::text]))))
);

--
-- Name: oauth_clients; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_clients (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    client_id text NOT NULL,
    client_secret_hash text NOT NULL,
    name text NOT NULL,
    redirect_uris text[] DEFAULT '{}'::text[] NOT NULL,
    grant_types text[] DEFAULT '{client_credentials}'::text[] NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_clients_status_check CHECK ((status = ANY (ARRAY['active'::text, 'revoked'::text])))
);

--
-- Name: oauth_tokens; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.oauth_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    client_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    token_hash text NOT NULL,
    token_type text NOT NULL,
    scopes text[] DEFAULT '{}'::text[] NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT oauth_tokens_token_type_check CHECK ((token_type = ANY (ARRAY['access'::text, 'refresh'::text])))
);

--
-- Name: pending_uploads; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.pending_uploads (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    blob_key character varying(512) CONSTRAINT pending_uploads_seaweedfs_fid_not_null NOT NULL,
    filename text NOT NULL,
    content_type text NOT NULL,
    size bigint NOT NULL,
    checksum_sha256 text,
    scan_status text DEFAULT 'pending'::text NOT NULL,
    scan_result text,
    claimed boolean DEFAULT false NOT NULL,
    expires_at timestamp with time zone DEFAULT (now() + '24:00:00'::interval) NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT pending_uploads_scan_status_check CHECK ((scan_status = ANY (ARRAY['pending'::text, 'clean'::text, 'infected'::text, 'error'::text])))
);

--
-- Name: smtp_credentials; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.smtp_credentials (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    username text NOT NULL,
    password_hash text NOT NULL,
    scram_stored_key text,
    scram_server_key text,
    scram_salt text,
    scram_iterations integer DEFAULT 4096,
    mechanisms text[] DEFAULT '{PLAIN,LOGIN}'::text[] NOT NULL,
    enabled boolean DEFAULT true NOT NULL,
    last_used timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: suppressions; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.suppressions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    email text NOT NULL,
    reason text NOT NULL,
    source_event_id uuid,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT suppressions_reason_check CHECK ((reason = ANY (ARRAY['hard_bounce'::text, 'complaint'::text, 'manual'::text, 'unsubscribe'::text])))
);

--
-- Name: tenant_ip_assignments; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenant_ip_assignments (
    tenant_id uuid NOT NULL,
    ip_pool_id uuid NOT NULL,
    priority integer DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: tenants; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tenants (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name text NOT NULL,
    tier text DEFAULT 'shared_standard'::text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    config jsonb DEFAULT '{}'::jsonb NOT NULL,
    rate_limits jsonb DEFAULT '{}'::jsonb NOT NULL,
    message_retention_days integer DEFAULT 90 NOT NULL,
    raw_eml_retention_days integer DEFAULT 30 NOT NULL,
    attachment_retention_days integer DEFAULT 30 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    verp_enabled boolean DEFAULT false NOT NULL,
    CONSTRAINT tenants_status_check CHECK ((status = ANY (ARRAY['active'::text, 'suspended'::text, 'deleted'::text]))),
    CONSTRAINT tenants_tier_check CHECK ((tier = ANY (ARRAY['dedicated'::text, 'shared_premium'::text, 'shared_standard'::text])))
);

--
-- Name: tlsrpt_reports; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tlsrpt_reports (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    domain_id uuid NOT NULL,
    direction text NOT NULL,
    report_id text NOT NULL,
    org_name text,
    date_begin timestamp with time zone NOT NULL,
    date_end timestamp with time zone NOT NULL,
    policy_type text NOT NULL,
    policy_domain text,
    total_success integer DEFAULT 0 NOT NULL,
    total_failure integer DEFAULT 0 NOT NULL,
    failure_details jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tlsrpt_reports_direction_check CHECK ((direction = ANY (ARRAY['inbound'::text, 'outbound'::text]))),
    CONSTRAINT tlsrpt_reports_policy_type_check CHECK ((policy_type = ANY (ARRAY['tlsa'::text, 'sts'::text, 'no-policy-found'::text])))
);

--
-- Name: tracking_certificates; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tracking_certificates (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tracking_domain_id uuid NOT NULL,
    certificate text NOT NULL,
    intermediaries text,
    private_key text NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    renew_after timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: tracking_domains; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.tracking_domains (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    domain_id uuid,
    domain_name text NOT NULL,
    cname_target text NOT NULL,
    dns_status text DEFAULT 'pending'::text NOT NULL,
    dns_error text,
    dns_checked_at timestamp with time zone,
    ssl_enabled boolean DEFAULT true NOT NULL,
    track_opens boolean DEFAULT true NOT NULL,
    track_clicks boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT tracking_domains_dns_status_check CHECK ((dns_status = ANY (ARRAY['pending'::text, 'verified'::text, 'failed'::text])))
);

--
-- Name: webhook_delivery_logs; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhook_delivery_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    webhook_id uuid NOT NULL,
    tenant_id uuid NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    http_status integer,
    response_body text,
    attempt_number integer DEFAULT 1 NOT NULL,
    delivered_at timestamp with time zone,
    failed_at timestamp with time zone,
    error_message text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);

--
-- Name: webhooks; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.webhooks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    tenant_id uuid NOT NULL,
    url text NOT NULL,
    event_types text[] NOT NULL,
    signing_secret text NOT NULL,
    status text DEFAULT 'active'::text NOT NULL,
    failure_count integer DEFAULT 0 NOT NULL,
    last_success_at timestamp with time zone,
    last_failure_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    CONSTRAINT webhooks_status_check CHECK ((status = ANY (ARRAY['active'::text, 'paused'::text, 'disabled'::text])))
);

--
-- Name: abuse_snapshots abuse_snapshots_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.abuse_snapshots
    ADD CONSTRAINT abuse_snapshots_pkey PRIMARY KEY (ip, snapshot_type);

--
-- Name: api_keys api_keys_key_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_key_hash_key UNIQUE (key_hash);

--
-- Name: api_keys api_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_pkey PRIMARY KEY (id);

--
-- Name: dkim_keys dkim_keys_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dkim_keys
    ADD CONSTRAINT dkim_keys_pkey PRIMARY KEY (id);

--
-- Name: dmarc_reports dmarc_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dmarc_reports
    ADD CONSTRAINT dmarc_reports_pkey PRIMARY KEY (id);

--
-- Name: dmarc_reports dmarc_reports_report_id_org_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dmarc_reports
    ADD CONSTRAINT dmarc_reports_report_id_org_name_key UNIQUE (report_id, org_name);

--
-- Name: domains domains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_pkey PRIMARY KEY (id);

--
-- Name: domains domains_tenant_id_domain_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_tenant_id_domain_name_key UNIQUE (tenant_id, domain_name);

--
-- Name: engagement_events engagement_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.engagement_events
    ADD CONSTRAINT engagement_events_pkey PRIMARY KEY (id, created_at);

--
-- Name: error_events error_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.error_events
    ADD CONSTRAINT error_events_pkey PRIMARY KEY (id);

--
-- Name: fbl_reports fbl_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fbl_reports
    ADD CONSTRAINT fbl_reports_pkey PRIMARY KEY (id);

--
-- Name: inbound_route_delivery_logs inbound_route_delivery_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbound_route_delivery_logs
    ADD CONSTRAINT inbound_route_delivery_logs_pkey PRIMARY KEY (id);

--
-- Name: inbound_routes inbound_routes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbound_routes
    ADD CONSTRAINT inbound_routes_pkey PRIMARY KEY (id);

--
-- Name: ip_pools ip_pools_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_pools
    ADD CONSTRAINT ip_pools_pkey PRIMARY KEY (id);

--
-- Name: ip_warmup_schedules ip_warmup_schedules_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_warmup_schedules
    ADD CONSTRAINT ip_warmup_schedules_pkey PRIMARY KEY (id);

--
-- Name: mailboxes mailboxes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailboxes
    ADD CONSTRAINT mailboxes_pkey PRIMARY KEY (id);

--
-- Name: message_attachments message_attachments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_attachments
    ADD CONSTRAINT message_attachments_pkey PRIMARY KEY (id, created_at);

--
-- Name: message_events message_events_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.message_events
    ADD CONSTRAINT message_events_pkey PRIMARY KEY (id, created_at);

--
-- Name: messages messages_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.messages
    ADD CONSTRAINT messages_pkey PRIMARY KEY (id, created_at);

--
-- Name: oauth_authorization_codes oauth_authorization_codes_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_authorization_codes
    ADD CONSTRAINT oauth_authorization_codes_pkey PRIMARY KEY (code);

--
-- Name: oauth_clients oauth_clients_client_id_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_client_id_key UNIQUE (client_id);

--
-- Name: oauth_clients oauth_clients_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_pkey PRIMARY KEY (id);

--
-- Name: oauth_tokens oauth_tokens_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_tokens
    ADD CONSTRAINT oauth_tokens_pkey PRIMARY KEY (id);

--
-- Name: oauth_tokens oauth_tokens_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_tokens
    ADD CONSTRAINT oauth_tokens_token_hash_key UNIQUE (token_hash);

--
-- Name: pending_uploads pending_uploads_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_uploads
    ADD CONSTRAINT pending_uploads_pkey PRIMARY KEY (id);

--
-- Name: smtp_credentials smtp_credentials_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smtp_credentials
    ADD CONSTRAINT smtp_credentials_pkey PRIMARY KEY (id);

--
-- Name: smtp_credentials smtp_credentials_tenant_id_username_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smtp_credentials
    ADD CONSTRAINT smtp_credentials_tenant_id_username_key UNIQUE (tenant_id, username);

--
-- Name: suppressions suppressions_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suppressions
    ADD CONSTRAINT suppressions_pkey PRIMARY KEY (id);

--
-- Name: suppressions suppressions_tenant_id_email_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suppressions
    ADD CONSTRAINT suppressions_tenant_id_email_key UNIQUE (tenant_id, email);

--
-- Name: tenant_ip_assignments tenant_ip_assignments_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_ip_assignments
    ADD CONSTRAINT tenant_ip_assignments_pkey PRIMARY KEY (tenant_id, ip_pool_id);

--
-- Name: tenants tenants_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenants
    ADD CONSTRAINT tenants_pkey PRIMARY KEY (id);

--
-- Name: tlsrpt_reports tlsrpt_reports_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tlsrpt_reports
    ADD CONSTRAINT tlsrpt_reports_pkey PRIMARY KEY (id);

--
-- Name: tlsrpt_reports tlsrpt_reports_report_id_org_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tlsrpt_reports
    ADD CONSTRAINT tlsrpt_reports_report_id_org_name_key UNIQUE (report_id, org_name);

--
-- Name: tracking_certificates tracking_certificates_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tracking_certificates
    ADD CONSTRAINT tracking_certificates_pkey PRIMARY KEY (id);

--
-- Name: tracking_domains tracking_domains_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tracking_domains
    ADD CONSTRAINT tracking_domains_pkey PRIMARY KEY (id);

--
-- Name: tracking_domains tracking_domains_tenant_id_domain_name_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tracking_domains
    ADD CONSTRAINT tracking_domains_tenant_id_domain_name_key UNIQUE (tenant_id, domain_name);

--
-- Name: webhook_delivery_logs webhook_delivery_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_delivery_logs
    ADD CONSTRAINT webhook_delivery_logs_pkey PRIMARY KEY (id);

--
-- Name: webhooks webhooks_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhooks
    ADD CONSTRAINT webhooks_pkey PRIMARY KEY (id);

--
-- Name: dkim_keys_active_selector_uniq; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX dkim_keys_active_selector_uniq ON public.dkim_keys USING btree (domain_id, selector) WHERE (status = 'active'::text);

--
-- Name: idx_engagement_message; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_engagement_message ON ONLY public.engagement_events USING btree (message_id);

--
-- Name: idx_engagement_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_engagement_client ON ONLY public.engagement_events USING btree (tenant_id, client_name) WHERE (client_name IS NOT NULL);

--
-- Name: idx_engagement_country; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_engagement_country ON ONLY public.engagement_events USING btree (tenant_id, country_code) WHERE (country_code IS NOT NULL);

--
-- Name: idx_engagement_tenant_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_engagement_tenant_type ON ONLY public.engagement_events USING btree (tenant_id, event_type, created_at DESC);

--
-- Name: idx_abuse_snapshots_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_abuse_snapshots_type ON public.abuse_snapshots USING btree (snapshot_type);

--
-- Name: idx_api_keys_prefix; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_prefix ON public.api_keys USING btree (key_prefix);

--
-- Name: idx_api_keys_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_api_keys_tenant ON public.api_keys USING btree (tenant_id);

--
-- Name: idx_attachments_message; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attachments_message ON ONLY public.message_attachments USING btree (message_id);

--
-- Name: idx_attachments_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_attachments_tenant ON ONLY public.message_attachments USING btree (tenant_id);

--
-- Name: idx_dkim_keys_active_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dkim_keys_active_lookup ON public.dkim_keys USING btree (domain_id, status) WHERE (status = 'active'::text);

--
-- Name: idx_dkim_keys_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dkim_keys_domain ON public.dkim_keys USING btree (domain_id);

--
-- Name: idx_dmarc_reports_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dmarc_reports_domain ON public.dmarc_reports USING btree (domain_id, date_begin DESC);

--
-- Name: idx_dmarc_reports_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_dmarc_reports_tenant ON public.dmarc_reports USING btree (tenant_id, date_begin DESC);

--
-- Name: idx_domains_name; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_domains_name ON public.domains USING btree (domain_name);

--
-- Name: idx_domains_name_unique; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_domains_name_unique ON public.domains USING btree (domain_name) WHERE (status = 'verified'::text);

--
-- Name: idx_domains_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_domains_tenant ON public.domains USING btree (tenant_id);

--
-- Name: idx_error_events_component_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_error_events_component_created ON public.error_events USING btree (component, created_at DESC);

--
-- Name: idx_error_events_message_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_error_events_message_id ON public.error_events USING btree (message_id) WHERE (message_id IS NOT NULL);

--
-- Name: idx_error_events_severity_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_error_events_severity_created ON public.error_events USING btree (severity, created_at DESC);

--
-- Name: idx_error_events_tenant_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_error_events_tenant_created ON public.error_events USING btree (tenant_id, created_at DESC);

--
-- Name: idx_events_message; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_message ON ONLY public.message_events USING btree (message_id);

--
-- Name: idx_events_tenant_type; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_events_tenant_type ON ONLY public.message_events USING btree (tenant_id, event_type, created_at DESC);

--
-- Name: idx_fbl_message; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fbl_message ON public.fbl_reports USING btree (original_message_id) WHERE (original_message_id IS NOT NULL);

--
-- Name: idx_fbl_recipient; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fbl_recipient ON public.fbl_reports USING btree (complained_recipient);

--
-- Name: idx_fbl_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_fbl_tenant ON public.fbl_reports USING btree (tenant_id, created_at DESC);

--
-- Name: idx_inbound_route_logs_message; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inbound_route_logs_message ON public.inbound_route_delivery_logs USING btree (message_id) WHERE (message_id IS NOT NULL);

--
-- Name: idx_inbound_route_logs_route; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inbound_route_logs_route ON public.inbound_route_delivery_logs USING btree (inbound_route_id, created_at DESC);

--
-- Name: idx_inbound_route_logs_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inbound_route_logs_tenant ON public.inbound_route_delivery_logs USING btree (tenant_id, created_at DESC);

--
-- Name: idx_inbound_routes_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_inbound_routes_tenant ON public.inbound_routes USING btree (tenant_id);

--
-- Name: idx_mailboxes_address; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_mailboxes_address ON public.mailboxes USING btree (domain_id, lower(address));

--
-- Name: idx_mailboxes_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mailboxes_domain ON public.mailboxes USING btree (domain_id);

--
-- Name: idx_mailboxes_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_mailboxes_tenant ON public.mailboxes USING btree (tenant_id);

--
-- Name: idx_messages_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_domain ON ONLY public.messages USING btree (domain_id) WHERE (domain_id IS NOT NULL);

--
-- Name: idx_messages_message_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_message_id ON ONLY public.messages USING btree (message_id_header) WHERE (message_id_header IS NOT NULL);

--
-- Name: idx_messages_scheduled; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_scheduled ON ONLY public.messages USING btree (send_at) WHERE (status = 'scheduled'::text);

--
-- Name: idx_messages_status; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_status ON ONLY public.messages USING btree (status) WHERE (status <> ALL (ARRAY['delivered'::text, 'dropped'::text]));

--
-- Name: idx_messages_tenant_created; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_messages_tenant_created ON ONLY public.messages USING btree (tenant_id, created_at DESC);

--
-- Name: idx_oauth_clients_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_clients_tenant ON public.oauth_clients USING btree (tenant_id);

--
-- Name: idx_oauth_codes_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_codes_expires ON public.oauth_authorization_codes USING btree (expires_at);

--
-- Name: idx_oauth_tokens_client; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_tokens_client ON public.oauth_tokens USING btree (client_id);

--
-- Name: idx_oauth_tokens_expires; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_oauth_tokens_expires ON public.oauth_tokens USING btree (expires_at) WHERE (revoked_at IS NULL);

--
-- Name: idx_pending_uploads_orphans; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pending_uploads_orphans ON public.pending_uploads USING btree (expires_at) WHERE (claimed = false);

--
-- Name: idx_pending_uploads_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_pending_uploads_tenant ON public.pending_uploads USING btree (tenant_id);

--
-- Name: idx_smtp_creds_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_smtp_creds_lookup ON public.smtp_credentials USING btree (username) WHERE (enabled = true);

--
-- Name: idx_smtp_creds_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_smtp_creds_tenant ON public.smtp_credentials USING btree (tenant_id);

--
-- Name: idx_suppressions_lookup; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_suppressions_lookup ON public.suppressions USING btree (tenant_id, email);

--
-- Name: idx_tlsrpt_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tlsrpt_domain ON public.tlsrpt_reports USING btree (domain_id, date_begin DESC);

--
-- Name: idx_tlsrpt_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tlsrpt_tenant ON public.tlsrpt_reports USING btree (tenant_id, date_begin DESC);

--
-- Name: idx_tracking_certs_domain; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tracking_certs_domain ON public.tracking_certificates USING btree (tracking_domain_id);

--
-- Name: idx_tracking_certs_renew; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tracking_certs_renew ON public.tracking_certificates USING btree (renew_after);

--
-- Name: idx_tracking_domains_name; Type: INDEX; Schema: public; Owner: -
--

CREATE UNIQUE INDEX idx_tracking_domains_name ON public.tracking_domains USING btree (domain_name);

--
-- Name: idx_tracking_domains_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tracking_domains_tenant ON public.tracking_domains USING btree (tenant_id);

--
-- Name: idx_warmup_active; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_warmup_active ON public.ip_warmup_schedules USING btree (status) WHERE (status = ANY (ARRAY['scheduled'::text, 'in_progress'::text]));

--
-- Name: idx_warmup_pool; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_warmup_pool ON public.ip_warmup_schedules USING btree (ip_pool_id);

--
-- Name: idx_warmup_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_warmup_tenant ON public.ip_warmup_schedules USING btree (tenant_id);

--
-- Name: idx_webhook_logs_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_logs_tenant ON public.webhook_delivery_logs USING btree (tenant_id, created_at DESC);

--
-- Name: idx_webhook_logs_webhook; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhook_logs_webhook ON public.webhook_delivery_logs USING btree (webhook_id, created_at DESC);

--
-- Name: idx_webhooks_tenant; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_webhooks_tenant ON public.webhooks USING btree (tenant_id);

--
-- Name: domains trg_domains_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_domains_updated_at BEFORE UPDATE ON public.domains FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

--
-- Name: oauth_clients trg_oauth_clients_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_oauth_clients_updated_at BEFORE UPDATE ON public.oauth_clients FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

--
-- Name: smtp_credentials trg_smtp_credentials_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_smtp_credentials_updated_at BEFORE UPDATE ON public.smtp_credentials FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

--
-- Name: tenants trg_tenants_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_tenants_updated_at BEFORE UPDATE ON public.tenants FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

--
-- Name: tracking_domains trg_tracking_domains_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_tracking_domains_updated_at BEFORE UPDATE ON public.tracking_domains FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

--
-- Name: ip_warmup_schedules trg_warmup_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_warmup_updated_at BEFORE UPDATE ON public.ip_warmup_schedules FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

--
-- Name: webhooks trg_webhooks_updated_at; Type: TRIGGER; Schema: public; Owner: -
--

CREATE TRIGGER trg_webhooks_updated_at BEFORE UPDATE ON public.webhooks FOR EACH ROW EXECUTE FUNCTION public.set_updated_at();

--
-- Name: api_keys api_keys_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.api_keys
    ADD CONSTRAINT api_keys_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: dkim_keys dkim_keys_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dkim_keys
    ADD CONSTRAINT dkim_keys_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;

--
-- Name: dmarc_reports dmarc_reports_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dmarc_reports
    ADD CONSTRAINT dmarc_reports_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;

--
-- Name: dmarc_reports dmarc_reports_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.dmarc_reports
    ADD CONSTRAINT dmarc_reports_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: domains domains_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.domains
    ADD CONSTRAINT domains_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: error_events error_events_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.error_events
    ADD CONSTRAINT error_events_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: fbl_reports fbl_reports_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.fbl_reports
    ADD CONSTRAINT fbl_reports_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: inbound_route_delivery_logs inbound_route_delivery_logs_inbound_route_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbound_route_delivery_logs
    ADD CONSTRAINT inbound_route_delivery_logs_inbound_route_id_fkey FOREIGN KEY (inbound_route_id) REFERENCES public.inbound_routes(id) ON DELETE CASCADE;

--
-- Name: inbound_route_delivery_logs inbound_route_delivery_logs_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbound_route_delivery_logs
    ADD CONSTRAINT inbound_route_delivery_logs_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: inbound_routes inbound_routes_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.inbound_routes
    ADD CONSTRAINT inbound_routes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: ip_warmup_schedules ip_warmup_schedules_ip_pool_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_warmup_schedules
    ADD CONSTRAINT ip_warmup_schedules_ip_pool_id_fkey FOREIGN KEY (ip_pool_id) REFERENCES public.ip_pools(id) ON DELETE CASCADE;

--
-- Name: ip_warmup_schedules ip_warmup_schedules_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.ip_warmup_schedules
    ADD CONSTRAINT ip_warmup_schedules_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: mailboxes mailboxes_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailboxes
    ADD CONSTRAINT mailboxes_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;

--
-- Name: mailboxes mailboxes_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.mailboxes
    ADD CONSTRAINT mailboxes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: oauth_authorization_codes oauth_authorization_codes_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_authorization_codes
    ADD CONSTRAINT oauth_authorization_codes_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth_clients(id) ON DELETE CASCADE;

--
-- Name: oauth_authorization_codes oauth_authorization_codes_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_authorization_codes
    ADD CONSTRAINT oauth_authorization_codes_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: oauth_clients oauth_clients_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_clients
    ADD CONSTRAINT oauth_clients_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: oauth_tokens oauth_tokens_client_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_tokens
    ADD CONSTRAINT oauth_tokens_client_id_fkey FOREIGN KEY (client_id) REFERENCES public.oauth_clients(id) ON DELETE CASCADE;

--
-- Name: oauth_tokens oauth_tokens_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.oauth_tokens
    ADD CONSTRAINT oauth_tokens_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: pending_uploads pending_uploads_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.pending_uploads
    ADD CONSTRAINT pending_uploads_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: smtp_credentials smtp_credentials_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.smtp_credentials
    ADD CONSTRAINT smtp_credentials_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: suppressions suppressions_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.suppressions
    ADD CONSTRAINT suppressions_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: tenant_ip_assignments tenant_ip_assignments_ip_pool_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_ip_assignments
    ADD CONSTRAINT tenant_ip_assignments_ip_pool_id_fkey FOREIGN KEY (ip_pool_id) REFERENCES public.ip_pools(id) ON DELETE CASCADE;

--
-- Name: tenant_ip_assignments tenant_ip_assignments_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tenant_ip_assignments
    ADD CONSTRAINT tenant_ip_assignments_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: tlsrpt_reports tlsrpt_reports_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tlsrpt_reports
    ADD CONSTRAINT tlsrpt_reports_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE CASCADE;

--
-- Name: tlsrpt_reports tlsrpt_reports_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tlsrpt_reports
    ADD CONSTRAINT tlsrpt_reports_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: tracking_certificates tracking_certificates_tracking_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tracking_certificates
    ADD CONSTRAINT tracking_certificates_tracking_domain_id_fkey FOREIGN KEY (tracking_domain_id) REFERENCES public.tracking_domains(id) ON DELETE CASCADE;

--
-- Name: tracking_domains tracking_domains_domain_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tracking_domains
    ADD CONSTRAINT tracking_domains_domain_id_fkey FOREIGN KEY (domain_id) REFERENCES public.domains(id) ON DELETE SET NULL;

--
-- Name: tracking_domains tracking_domains_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.tracking_domains
    ADD CONSTRAINT tracking_domains_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

--
-- Name: webhook_delivery_logs webhook_delivery_logs_webhook_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhook_delivery_logs
    ADD CONSTRAINT webhook_delivery_logs_webhook_id_fkey FOREIGN KEY (webhook_id) REFERENCES public.webhooks(id) ON DELETE CASCADE;

--
-- Name: webhooks webhooks_tenant_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.webhooks
    ADD CONSTRAINT webhooks_tenant_id_fkey FOREIGN KEY (tenant_id) REFERENCES public.tenants(id) ON DELETE CASCADE;

-- =============================================================================
-- Monthly partitions: current month plus the next two
-- =============================================================================
-- The runtime extends this window by calling sentio_create_month_partitions().
--
-- Pinned to UTC to match sentio_create_month_partitions(). Both compute month
-- boundaries as DATEs that Postgres then resolves against the prevailing zone;
-- if the two disagree the bounds land an hour or two apart and the function
-- fails with "would overlap" the first time it tries to extend this window.
SET LOCAL TimeZone = 'UTC';

DO $$
DECLARE
    month_start DATE;
    month_end   DATE;
    part_suffix TEXT;
    tbl         TEXT;
BEGIN
    FOR i IN 0..2 LOOP
        month_start := date_trunc('month', CURRENT_DATE + (i || ' months')::INTERVAL)::DATE;
        month_end   := (month_start + INTERVAL '1 month')::DATE;
        part_suffix := to_char(month_start, 'YYYY_MM');

        FOREACH tbl IN ARRAY ARRAY['messages', 'message_events', 'engagement_events', 'message_attachments']
        LOOP
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I
                    FOR VALUES FROM (%L) TO (%L)',
                tbl || '_' || part_suffix, tbl, month_start, month_end
            );
        END LOOP;
    END LOOP;
END;
$$;
