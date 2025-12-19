-- Nginx Proxy Guard - Initial Schema
-- This file is IDEMPOTENT - safe to run multiple times
-- Uses IF NOT EXISTS for all objects

-- Extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ENUM Types (wrapped in DO blocks to handle existing types)
DO $$ BEGIN
    CREATE TYPE public.block_reason AS ENUM (
        'none', 'waf', 'bot_filter', 'rate_limit', 'geo_block', 'exploit_block', 'banned_ip', 'uri_block', 'cloud_provider_challenge'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE public.log_severity AS ENUM (
        'debug', 'info', 'notice', 'warn', 'error', 'crit', 'alert', 'emerg'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE public.log_type AS ENUM ('access', 'error', 'modsec');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE public.system_log_level AS ENUM ('debug', 'info', 'warn', 'error', 'fatal');
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;

DO $$ BEGIN
    CREATE TYPE public.system_log_source AS ENUM (
        'docker_api', 'docker_nginx', 'docker_db', 'docker_ui', 'health_check',
        'internal', 'scheduler', 'backup', 'certificate', 'audit', 'api_token'
    );
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE OR REPLACE FUNCTION public.cleanup_expired_challenge_tokens() RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM challenge_tokens
    WHERE expires_at < NOW() - INTERVAL '1 day';
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;
CREATE OR REPLACE FUNCTION public.cleanup_old_logs(retention_days integer DEFAULT 30) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM logs
    WHERE created_at < NOW() - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;
CREATE OR REPLACE FUNCTION public.cleanup_system_logs(retention_days integer DEFAULT 7) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    deleted_count INTEGER;
BEGIN
    DELETE FROM system_logs
    WHERE created_at < NOW() - (retention_days || ' days')::INTERVAL;
    GET DIAGNOSTICS deleted_count = ROW_COUNT;
    RETURN deleted_count;
END;
$$;
CREATE OR REPLACE FUNCTION public.create_monthly_partitions(table_name text, partition_prefix text, months_ahead integer DEFAULT 3) RETURNS void
    LANGUAGE plpgsql
    AS $$
DECLARE
    start_date DATE;
    end_date DATE;
    partition_name TEXT;
    i INT;
BEGIN
    FOR i IN 0..months_ahead LOOP
        start_date := DATE_TRUNC('month', CURRENT_DATE + (i || ' months')::INTERVAL);
        end_date := start_date + INTERVAL '1 month';
        partition_name := partition_prefix || TO_CHAR(start_date, 'YYYY_MM');
        -- Check if partition exists
        IF NOT EXISTS (
            SELECT 1 FROM pg_class WHERE relname = partition_name
        ) THEN
            EXECUTE format(
                'CREATE TABLE IF NOT EXISTS %I PARTITION OF %I FOR VALUES FROM (%L) TO (%L)',
                partition_name, table_name, start_date, end_date
            );
            RAISE NOTICE 'Created partition: %', partition_name;
        END IF;
    END LOOP;
END;
$$;
CREATE OR REPLACE FUNCTION public.drop_old_partitions(partition_prefix text, retention_months integer DEFAULT 3) RETURNS integer
    LANGUAGE plpgsql
    AS $$
DECLARE
    partition_record RECORD;
    dropped_count INT := 0;
    cutoff_date DATE;
BEGIN
    cutoff_date := DATE_TRUNC('month', CURRENT_DATE - (retention_months || ' months')::INTERVAL);
    FOR partition_record IN
        SELECT tablename FROM pg_tables
        WHERE tablename LIKE partition_prefix || '%'
        AND tablename NOT LIKE '%_default'
    LOOP
        -- Extract date from partition name and compare
        IF partition_record.tablename < partition_prefix || TO_CHAR(cutoff_date, 'YYYY_MM') THEN
            EXECUTE format('DROP TABLE IF EXISTS %I', partition_record.tablename);
            dropped_count := dropped_count + 1;
            RAISE NOTICE 'Dropped partition: %', partition_record.tablename;
        END IF;
    END LOOP;
    RETURN dropped_count;
END;
$$;
CREATE OR REPLACE FUNCTION public.update_api_tokens_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION public.update_challenge_configs_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION public.update_cloud_providers_updated_at() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;
CREATE OR REPLACE FUNCTION public.update_updated_at_column() RETURNS trigger
    LANGUAGE plpgsql
    AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;
CREATE TABLE IF NOT EXISTS public.access_list_items (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    access_list_id uuid NOT NULL,
    directive character varying(10) NOT NULL,
    address character varying(255) NOT NULL,
    description text,
    sort_order integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT now(),
    CONSTRAINT access_list_items_directive_check CHECK (((directive)::text = ANY ((ARRAY['allow'::character varying, 'deny'::character varying])::text[])))
);
CREATE TABLE IF NOT EXISTS public.access_lists (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(255) NOT NULL,
    description text,
    satisfy_any boolean DEFAULT true,
    pass_auth boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.api_token_usage (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    token_id uuid NOT NULL,
    endpoint character varying(255) NOT NULL,
    method character varying(10) NOT NULL,
    status_code integer,
    client_ip character varying(45),
    user_agent text,
    request_body_size integer,
    response_time_ms integer,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.api_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    token_hash character varying(64) NOT NULL,
    token_prefix character varying(16) NOT NULL,
    permissions jsonb DEFAULT '["*"]'::jsonb NOT NULL,
    allowed_ips text[],
    rate_limit integer DEFAULT 1000,
    expires_at timestamp with time zone,
    last_used_at timestamp with time zone,
    last_used_ip character varying(45),
    use_count bigint DEFAULT 0,
    is_active boolean DEFAULT true NOT NULL,
    revoked_at timestamp with time zone,
    revoked_reason character varying(255),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.audit_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid,
    username character varying(255) NOT NULL,
    action character varying(100) NOT NULL,
    resource_type character varying(255),
    resource_id character varying(255),
    resource_name character varying(255),
    details jsonb,
    ip_address character varying(45),
    user_agent text,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.auth_sessions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    user_id uuid NOT NULL,
    token_hash character varying(255) NOT NULL,
    ip_address character varying(45),
    user_agent text,
    expires_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.backups (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    filename character varying(255) NOT NULL,
    file_size bigint DEFAULT 0 NOT NULL,
    file_path character varying(500) NOT NULL,
    includes_config boolean DEFAULT true NOT NULL,
    includes_certificates boolean DEFAULT true NOT NULL,
    includes_database boolean DEFAULT true NOT NULL,
    backup_type character varying(20) DEFAULT 'manual'::character varying NOT NULL,
    description text,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    error_message text,
    checksum_sha256 character varying(64),
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    completed_at timestamp with time zone
);
CREATE TABLE IF NOT EXISTS public.banned_ips (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    ip_address character varying(45) NOT NULL,
    reason character varying(255),
    fail_count integer DEFAULT 0,
    banned_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone,
    is_permanent boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    is_auto_banned boolean DEFAULT false
);
CREATE TABLE IF NOT EXISTS public.bot_filters (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid NOT NULL,
    enabled boolean DEFAULT true,
    block_bad_bots boolean DEFAULT true,
    block_ai_bots boolean DEFAULT false,
    allow_search_engines boolean DEFAULT true,
    custom_blocked_agents text,
    custom_allowed_agents text,
    challenge_suspicious boolean DEFAULT false,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    block_suspicious_clients boolean DEFAULT false
);
CREATE TABLE IF NOT EXISTS public.certificates (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    domain_names text[] NOT NULL,
    expires_at timestamp with time zone,
    certificate_path character varying(512),
    private_key_path character varying(512),
    provider character varying(50) DEFAULT 'letsencrypt'::character varying,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    dns_provider_id uuid,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    acme_account jsonb DEFAULT '{}'::jsonb,
    auto_renew boolean DEFAULT true NOT NULL,
    renewal_attempted_at timestamp with time zone,
    issued_at timestamp with time zone,
    error_message text,
    certificate_pem text,
    private_key_pem text,
    issuer_certificate_pem text
);
COMMENT ON COLUMN public.certificates.status IS 'Certificate status: pending, issued, expired, error, renewing';
COMMENT ON COLUMN public.certificates.acme_account IS 'ACME account registration data';
COMMENT ON COLUMN public.certificates.certificate_pem IS 'Full certificate chain in PEM format';
COMMENT ON COLUMN public.certificates.private_key_pem IS 'Private key in PEM format (encrypted at rest)';
COMMENT ON COLUMN public.certificates.issuer_certificate_pem IS 'Issuer/CA certificate';
CREATE TABLE IF NOT EXISTS public.certificate_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    certificate_id uuid NOT NULL,
    action character varying(50) NOT NULL,
    status character varying(50) NOT NULL,
    message text,
    domain_names text[] NOT NULL,
    provider character varying(50) NOT NULL,
    expires_at timestamp with time zone,
    logs jsonb,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE public.certificate_history IS 'Certificate issuance and renewal history';
COMMENT ON COLUMN public.certificate_history.action IS 'Action type: issued, renewed, error, expired';
COMMENT ON COLUMN public.certificate_history.status IS 'Result status: success, error';
COMMENT ON COLUMN public.certificate_history.logs IS 'JSON array of log entries from ACME process';
CREATE TABLE IF NOT EXISTS public.challenge_configs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    enabled boolean DEFAULT true,
    challenge_type character varying(20) DEFAULT 'recaptcha_v2'::character varying,
    site_key character varying(255),
    secret_key character varying(255),
    token_validity integer DEFAULT 86400,
    min_score numeric(3,2) DEFAULT 0.5,
    apply_to character varying(20) DEFAULT 'both'::character varying,
    page_title character varying(255) DEFAULT 'Security Check'::character varying,
    page_message text DEFAULT 'Please complete the security check to continue.'::text,
    theme character varying(10) DEFAULT 'light'::character varying,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.challenge_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    client_ip character varying(45) NOT NULL,
    user_agent text,
    result character varying(20) NOT NULL,
    trigger_reason character varying(255),
    captcha_score numeric(3,2),
    solve_time integer,
    created_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.challenge_tokens (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    token_hash character varying(64) NOT NULL,
    client_ip character varying(45) NOT NULL,
    user_agent text,
    challenge_reason character varying(255),
    issued_at timestamp with time zone DEFAULT now(),
    expires_at timestamp with time zone NOT NULL,
    use_count integer DEFAULT 0,
    last_used_at timestamp with time zone,
    revoked boolean DEFAULT false,
    revoked_at timestamp with time zone,
    revoked_reason character varying(255)
);
CREATE TABLE IF NOT EXISTS public.cloud_providers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    name character varying(100) NOT NULL,
    slug character varying(50) NOT NULL,
    region character varying(50) NOT NULL,
    description text,
    ip_ranges text[] DEFAULT '{}'::text[] NOT NULL,
    ip_ranges_url character varying(500),
    last_updated timestamp with time zone,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);

-- Insert default cloud providers with sample IP ranges
-- US Providers
INSERT INTO public.cloud_providers (name, slug, region, description, ip_ranges, ip_ranges_url) VALUES
('Amazon Web Services', 'aws', 'us', 'Amazon cloud services (EC2, Lambda, etc.)',
 ARRAY['3.0.0.0/8', '13.32.0.0/12', '15.177.0.0/16', '18.0.0.0/8', '23.20.0.0/14', '34.192.0.0/10', '35.153.0.0/16', '44.192.0.0/10', '50.16.0.0/14', '52.0.0.0/10', '54.64.0.0/11', '54.144.0.0/12', '54.160.0.0/11', '54.192.0.0/12', '54.208.0.0/13', '54.216.0.0/14', '54.220.0.0/15', '54.224.0.0/12', '54.240.0.0/12', '63.32.0.0/14', '64.252.0.0/16', '72.21.192.0/19', '75.101.128.0/17', '79.125.0.0/17', '99.77.128.0/17', '99.78.0.0/16', '99.79.0.0/16', '99.80.0.0/15', '100.20.0.0/14', '107.20.0.0/14', '174.129.0.0/16', '176.32.96.0/19', '184.72.0.0/15', '184.169.128.0/17', '185.48.120.0/22', '203.83.220.0/22', '204.236.128.0/17', '205.251.192.0/18', '207.171.160.0/19', '216.182.224.0/20'],
 'https://ip-ranges.amazonaws.com/ip-ranges.json'),
('Microsoft Azure', 'azure', 'us', 'Microsoft cloud platform',
 ARRAY['13.64.0.0/11', '13.96.0.0/13', '13.104.0.0/14', '20.33.0.0/16', '20.34.0.0/15', '20.36.0.0/14', '20.40.0.0/13', '20.48.0.0/12', '20.64.0.0/10', '20.128.0.0/16', '23.96.0.0/13', '40.64.0.0/10', '40.112.0.0/13', '51.104.0.0/14', '51.120.0.0/14', '52.96.0.0/12', '52.112.0.0/14', '52.120.0.0/14', '52.136.0.0/13', '52.146.0.0/15', '52.148.0.0/14', '52.152.0.0/13', '52.160.0.0/11', '52.224.0.0/11', '65.52.0.0/14', '70.37.0.0/17', '104.40.0.0/13', '104.208.0.0/13', '157.55.0.0/16', '168.61.0.0/16', '168.62.0.0/15', '191.232.0.0/13', '204.79.180.0/24', '207.46.0.0/16'],
 'https://www.microsoft.com/en-us/download/details.aspx?id=56519'),
('Google Cloud', 'gcp', 'us', 'Google Cloud Platform',
 ARRAY['8.34.208.0/20', '8.35.192.0/20', '23.236.48.0/20', '23.251.128.0/19', '34.64.0.0/10', '34.128.0.0/10', '35.184.0.0/13', '35.192.0.0/12', '35.208.0.0/12', '35.224.0.0/12', '35.240.0.0/13', '104.154.0.0/15', '104.196.0.0/14', '107.167.160.0/19', '107.178.192.0/18', '108.59.80.0/20', '108.170.192.0/18', '130.211.0.0/16', '142.250.0.0/15', '146.148.0.0/17', '162.216.148.0/22', '162.222.176.0/21', '172.110.32.0/21', '172.217.0.0/16', '172.253.0.0/16', '173.194.0.0/16', '173.255.112.0/20', '192.158.28.0/22', '193.186.4.0/24', '199.36.153.0/24', '199.36.154.0/23', '199.192.112.0/22', '199.223.232.0/21', '208.65.152.0/22', '208.68.108.0/22', '208.81.188.0/22', '208.117.224.0/19', '209.85.128.0/17', '216.58.192.0/19', '216.239.32.0/19'],
 'https://www.gstatic.com/ipranges/cloud.json'),
('DigitalOcean', 'digitalocean', 'us', 'DigitalOcean cloud hosting',
 ARRAY['24.199.64.0/18', '45.55.0.0/16', '64.225.0.0/16', '67.205.128.0/17', '68.183.0.0/16', '104.131.0.0/16', '104.236.0.0/16', '107.170.0.0/16', '128.199.0.0/16', '134.122.0.0/16', '134.209.0.0/16', '137.184.0.0/16', '138.68.0.0/16', '138.197.0.0/16', '139.59.0.0/16', '142.93.0.0/16', '143.110.0.0/16', '143.198.0.0/16', '144.126.192.0/18', '146.190.0.0/16', '157.230.0.0/16', '157.245.0.0/16', '159.65.0.0/16', '159.89.0.0/16', '159.203.0.0/16', '161.35.0.0/16', '162.243.0.0/16', '163.47.8.0/21', '165.22.0.0/16', '165.227.0.0/16', '167.71.0.0/16', '167.99.0.0/16', '167.172.0.0/16', '170.64.0.0/16', '174.138.0.0/16', '178.62.0.0/16', '178.128.0.0/16', '188.166.0.0/16', '192.34.56.0/21', '192.81.208.0/20', '192.241.128.0/17', '198.199.64.0/18', '198.211.96.0/19', '206.81.0.0/16', '206.189.0.0/16', '209.97.128.0/17'],
 NULL),
('Linode (Akamai)', 'linode', 'us', 'Linode/Akamai cloud hosting',
 ARRAY['23.92.16.0/20', '45.33.0.0/17', '45.56.64.0/18', '45.79.0.0/16', '50.116.0.0/18', '66.175.208.0/20', '66.228.32.0/19', '69.164.192.0/18', '72.14.176.0/20', '74.207.224.0/19', '85.90.244.0/22', '96.126.96.0/19', '97.107.128.0/17', '103.3.60.0/22', '109.74.192.0/19', '139.144.0.0/16', '139.162.0.0/16', '143.42.0.0/16', '172.104.0.0/15', '172.232.0.0/14', '173.230.128.0/18', '173.255.192.0/18', '176.58.88.0/21', '178.79.128.0/17', '185.3.92.0/22', '192.155.80.0/20', '194.195.112.0/21', '198.58.96.0/19', '198.74.48.0/20', '207.192.64.0/18', '209.123.160.0/19', '213.52.128.0/17', '213.168.248.0/21'],
 NULL),
('Oracle Cloud', 'oracle', 'us', 'Oracle Cloud Infrastructure',
 ARRAY['129.146.0.0/16', '129.148.0.0/15', '129.150.0.0/15', '129.152.0.0/16', '129.153.0.0/16', '129.154.0.0/15', '129.156.0.0/14', '130.35.0.0/16', '130.61.0.0/16', '132.145.0.0/16', '134.70.0.0/16', '137.254.0.0/16', '138.1.0.0/16', '140.204.0.0/16', '140.238.0.0/16', '141.144.0.0/14', '141.148.0.0/16', '144.21.0.0/16', '144.22.0.0/15', '144.24.0.0/13', '146.56.0.0/14', '147.154.0.0/16', '150.136.0.0/13', '152.67.0.0/16', '152.70.0.0/15', '155.248.0.0/16', '158.101.0.0/16', '158.178.0.0/15', '168.75.0.0/16', '168.138.0.0/15', '192.29.0.0/16', '193.122.0.0/16', '193.123.0.0/16', '199.195.0.0/17'],
 NULL),
('Vultr', 'vultr', 'us', 'Vultr cloud hosting',
 ARRAY['8.12.16.0/21', '8.9.4.0/22', '45.32.0.0/16', '45.63.0.0/16', '45.76.0.0/15', '64.156.192.0/19', '64.176.160.0/19', '66.42.32.0/19', '66.55.128.0/19', '67.219.96.0/19', '78.141.192.0/19', '80.240.16.0/20', '95.179.128.0/17', '104.156.224.0/19', '104.207.128.0/18', '108.61.0.0/16', '136.244.64.0/18', '137.220.32.0/19', '139.180.128.0/17', '140.82.0.0/17', '141.164.32.0/19', '144.202.0.0/16', '149.28.0.0/16', '149.248.0.0/17', '155.138.128.0/17', '158.247.192.0/18', '167.179.0.0/17', '192.248.128.0/17', '198.13.32.0/19', '199.247.0.0/16', '202.182.96.0/19', '207.148.64.0/18', '208.167.224.0/19', '209.250.224.0/19', '216.128.128.0/17', '217.163.0.0/17'],
 NULL)
ON CONFLICT (slug) DO NOTHING;

-- European Providers
INSERT INTO public.cloud_providers (name, slug, region, description, ip_ranges) VALUES
('Contabo', 'contabo', 'eu', 'German cloud hosting provider',
 ARRAY['5.189.128.0/17', '38.242.128.0/17', '45.129.180.0/22', '45.136.28.0/22', '45.138.72.0/22', '45.142.176.0/22', '45.144.28.0/22', '45.147.196.0/22', '62.171.128.0/17', '64.176.0.0/18', '77.37.32.0/19', '77.68.64.0/19', '78.46.0.0/15', '79.143.176.0/20', '80.240.16.0/21', '81.169.128.0/17', '82.165.0.0/16', '85.209.0.0/17', '87.106.0.0/16', '91.107.128.0/17', '91.194.84.0/22', '93.104.208.0/20', '94.136.176.0/20', '116.202.0.0/16', '116.203.0.0/16', '128.140.0.0/17', '141.94.0.0/15', '144.91.64.0/18', '157.90.0.0/16', '158.220.64.0/18', '162.55.0.0/16', '167.235.0.0/16', '168.119.0.0/16', '178.238.224.0/20', '185.48.180.0/22', '185.107.56.0/22', '185.170.112.0/22', '185.194.140.0/22', '188.40.0.0/16', '193.26.156.0/22', '193.108.116.0/22', '194.163.128.0/17', '195.201.0.0/16', '207.180.192.0/18', '213.136.64.0/18', '213.239.192.0/18']),
('Hetzner', 'hetzner', 'eu', 'German hosting and cloud provider',
 ARRAY['5.9.0.0/16', '5.75.128.0/17', '23.88.0.0/17', '37.27.0.0/17', '46.4.0.0/16', '49.12.0.0/16', '49.13.0.0/16', '65.108.0.0/16', '65.109.0.0/16', '78.46.0.0/15', '78.47.0.0/16', '85.10.192.0/18', '88.99.0.0/16', '88.198.0.0/16', '91.107.128.0/17', '94.130.0.0/16', '95.216.0.0/15', '95.217.0.0/16', '116.202.0.0/16', '116.203.0.0/16', '128.140.0.0/17', '135.181.0.0/16', '136.243.0.0/16', '138.201.0.0/16', '142.132.128.0/17', '144.76.0.0/16', '148.251.0.0/16', '157.90.0.0/16', '159.69.0.0/16', '162.55.0.0/16', '167.233.0.0/17', '167.235.0.0/16', '168.119.0.0/16', '176.9.0.0/16', '178.63.0.0/16', '178.212.48.0/20', '185.112.144.0/21', '188.34.128.0/17', '188.40.0.0/16', '193.25.170.0/23', '193.110.6.0/23', '195.201.0.0/16', '213.133.96.0/19', '213.239.192.0/18']),
('OVH', 'ovh', 'eu', 'French cloud provider (OVHcloud)',
 ARRAY['5.135.0.0/16', '5.196.0.0/16', '5.39.0.0/17', '37.59.0.0/16', '37.187.0.0/16', '46.105.0.0/16', '51.38.0.0/16', '51.68.0.0/16', '51.75.0.0/16', '51.77.0.0/16', '51.79.0.0/16', '51.83.0.0/16', '51.89.0.0/16', '51.91.0.0/16', '51.161.0.0/16', '51.178.0.0/16', '51.195.0.0/16', '51.210.0.0/16', '51.254.0.0/16', '51.255.0.0/16', '54.36.0.0/16', '54.37.0.0/16', '54.38.0.0/16', '54.39.0.0/16', '57.128.0.0/17', '79.137.0.0/17', '87.98.128.0/17', '91.121.0.0/16', '91.134.0.0/16', '92.222.0.0/16', '94.23.0.0/16', '135.125.0.0/16', '137.74.0.0/16', '139.99.0.0/16', '141.94.0.0/16', '141.95.0.0/16', '145.239.0.0/16', '147.135.0.0/16', '149.56.0.0/16', '149.202.0.0/16', '151.80.0.0/16', '158.69.0.0/16', '164.132.0.0/16', '167.114.0.0/16', '176.31.0.0/16', '178.32.0.0/16', '178.33.0.0/16', '185.12.32.0/22', '188.165.0.0/16', '192.95.0.0/16', '193.70.0.0/17', '198.27.64.0/18', '198.50.128.0/17', '198.100.144.0/20', '213.186.32.0/19', '213.251.128.0/17', '217.182.0.0/16']),
('Scaleway', 'scaleway', 'eu', 'French cloud provider (formerly Online.net)',
 ARRAY['51.15.0.0/16', '51.158.0.0/15', '62.4.0.0/18', '62.210.0.0/16', '163.172.0.0/16', '195.154.0.0/16', '212.47.224.0/19', '212.83.128.0/17', '212.129.0.0/18'])
ON CONFLICT (slug) DO NOTHING;

-- Chinese Providers
INSERT INTO public.cloud_providers (name, slug, region, description, ip_ranges) VALUES
('Alibaba Cloud', 'alibaba', 'cn', 'Alibaba Cloud (Aliyun)',
 ARRAY['8.129.0.0/16', '8.130.0.0/15', '8.134.0.0/15', '8.136.0.0/13', '8.144.0.0/13', '8.152.0.0/14', '8.208.0.0/12', '39.96.0.0/13', '39.104.0.0/13', '39.144.0.0/13', '42.96.128.0/17', '42.120.0.0/15', '42.156.128.0/17', '47.52.0.0/14', '47.56.0.0/14', '47.74.0.0/15', '47.88.0.0/14', '47.92.0.0/14', '47.96.0.0/11', '47.236.0.0/14', '47.240.0.0/13', '47.250.0.0/15', '47.252.0.0/14', '59.82.0.0/15', '60.205.0.0/16', '101.37.0.0/16', '101.132.0.0/14', '101.200.0.0/15', '101.204.0.0/14', '106.11.0.0/16', '106.14.0.0/15', '112.124.0.0/14', '112.74.0.0/15', '114.55.0.0/16', '114.215.0.0/16', '115.28.0.0/15', '115.124.16.0/20', '116.62.0.0/15', '118.31.0.0/16', '118.178.0.0/16', '118.190.0.0/15', '119.23.0.0/16', '119.38.208.0/20', '120.24.0.0/14', '120.55.0.0/16', '120.76.0.0/14', '121.40.0.0/14', '121.196.0.0/14', '123.56.0.0/14', '123.206.0.0/15', '139.129.0.0/16', '139.196.0.0/14', '139.224.0.0/16', '140.205.0.0/16', '147.139.0.0/16', '149.129.0.0/16', '161.117.0.0/16', '182.92.0.0/15']),
('Tencent Cloud', 'tencent', 'cn', 'Tencent Cloud',
 ARRAY['1.12.0.0/14', '1.62.0.0/15', '1.117.0.0/16', '1.119.128.0/17', '42.194.128.0/17', '43.129.0.0/16', '43.132.0.0/16', '43.134.0.0/15', '43.136.0.0/13', '43.152.0.0/15', '43.154.0.0/15', '43.156.0.0/14', '45.113.64.0/18', '49.51.0.0/16', '49.232.0.0/14', '58.87.64.0/18', '81.68.0.0/14', '81.70.0.0/15', '94.191.0.0/17', '101.32.0.0/15', '101.34.0.0/15', '106.52.0.0/14', '106.54.0.0/16', '106.55.0.0/16', '111.229.0.0/16', '111.230.0.0/15', '114.132.0.0/16', '115.159.0.0/16', '118.24.0.0/15', '118.89.0.0/16', '118.126.64.0/18', '119.28.0.0/15', '119.45.0.0/16', '119.91.128.0/17', '121.4.0.0/15', '121.51.0.0/16', '123.206.0.0/15', '124.156.0.0/16', '124.220.0.0/14', '124.222.0.0/15', '129.28.0.0/16', '129.204.0.0/15', '129.211.0.0/16', '132.232.0.0/16', '134.175.0.0/16', '140.143.0.0/16', '144.34.160.0/20', '148.70.0.0/16', '150.109.0.0/16', '152.136.0.0/16', '154.8.128.0/17', '159.75.0.0/16', '162.14.0.0/16', '175.24.0.0/16', '175.27.128.0/17', '180.76.0.0/16', '182.254.0.0/16', '193.112.0.0/16', '203.195.128.0/17', '210.73.88.0/21', '211.159.128.0/17', '212.64.0.0/17', '212.129.128.0/18']),
('Huawei Cloud', 'huawei', 'cn', 'Huawei Cloud',
 ARRAY['110.238.64.0/18', '114.116.0.0/16', '114.115.128.0/17', '116.63.128.0/17', '116.204.0.0/15', '117.78.0.0/18', '119.3.0.0/16', '119.8.0.0/16', '121.36.0.0/14', '121.37.0.0/16', '122.112.128.0/17', '124.70.0.0/15', '124.71.0.0/16', '139.9.0.0/16', '139.159.128.0/17', '159.138.0.0/16', '180.76.0.0/16', '182.50.0.0/17', '218.4.160.0/19', '218.94.32.0/19'])
ON CONFLICT (slug) DO NOTHING;

-- Korean Providers
INSERT INTO public.cloud_providers (name, slug, region, description, ip_ranges) VALUES
('Smileserv (CloudV/iwinv)', 'smileserv', 'kr', 'Korean cloud hosting (CloudV, iwinv, Naver Cloud partnership)',
 ARRAY['27.96.128.0/17', '27.102.0.0/17', '49.247.192.0/18', '58.229.0.0/17', '59.6.0.0/18', '59.18.32.0/19', '61.97.64.0/18', '101.79.0.0/18', '106.10.0.0/16', '110.93.128.0/17', '112.175.0.0/17', '115.68.0.0/15', '118.67.128.0/17', '119.196.0.0/15', '121.254.128.0/17', '175.126.0.0/16', '180.70.0.0/16', '182.162.0.0/16', '183.111.0.0/17', '210.89.160.0/19', '211.47.64.0/18', '211.115.64.0/18', '211.189.0.0/18', '211.234.64.0/18', '218.38.0.0/16', '222.122.0.0/16', '222.231.0.0/17']),
('Naver Cloud', 'naver', 'kr', 'Naver Cloud Platform',
 ARRAY['101.79.0.0/18', '106.10.0.0/16', '110.93.128.0/17', '114.108.128.0/17', '117.52.0.0/16', '119.205.192.0/18', '125.209.192.0/18', '175.158.0.0/16', '180.210.32.0/19', '182.162.0.0/16', '183.111.0.0/17', '210.89.160.0/19', '211.249.40.0/21', '223.130.192.0/18']),
('KT Cloud', 'kt', 'kr', 'KT Cloud (Korea Telecom)',
 ARRAY['14.63.128.0/17', '27.122.128.0/17', '58.229.0.0/17', '59.29.0.0/18', '61.111.0.0/18', '116.125.0.0/16', '118.217.0.0/16', '119.200.0.0/16', '121.166.0.0/16', '175.115.0.0/16', '175.203.0.0/16', '203.238.128.0/17', '210.183.0.0/18', '211.35.0.0/17', '211.117.0.0/17', '211.189.0.0/17', '218.234.0.0/16', '220.85.0.0/17'])
ON CONFLICT (slug) DO NOTHING;

CREATE TABLE IF NOT EXISTS public.dashboard_stats_daily (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    day_bucket date NOT NULL,
    total_requests bigint DEFAULT 0 NOT NULL,
    status_2xx bigint DEFAULT 0 NOT NULL,
    status_3xx bigint DEFAULT 0 NOT NULL,
    status_4xx bigint DEFAULT 0 NOT NULL,
    status_5xx bigint DEFAULT 0 NOT NULL,
    avg_response_time double precision DEFAULT 0,
    max_response_time double precision DEFAULT 0,
    bytes_sent bigint DEFAULT 0 NOT NULL,
    bytes_received bigint DEFAULT 0 NOT NULL,
    waf_blocked bigint DEFAULT 0 NOT NULL,
    rate_limited bigint DEFAULT 0 NOT NULL,
    bot_blocked bigint DEFAULT 0 NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.dashboard_stats_hourly (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    hour_bucket timestamp with time zone NOT NULL,
    total_requests bigint DEFAULT 0 NOT NULL,
    status_2xx bigint DEFAULT 0 NOT NULL,
    status_3xx bigint DEFAULT 0 NOT NULL,
    status_4xx bigint DEFAULT 0 NOT NULL,
    status_5xx bigint DEFAULT 0 NOT NULL,
    avg_response_time double precision DEFAULT 0,
    max_response_time double precision DEFAULT 0,
    min_response_time double precision DEFAULT 0,
    p95_response_time double precision DEFAULT 0,
    p99_response_time double precision DEFAULT 0,
    bytes_sent bigint DEFAULT 0 NOT NULL,
    bytes_received bigint DEFAULT 0 NOT NULL,
    waf_blocked bigint DEFAULT 0 NOT NULL,
    waf_detected bigint DEFAULT 0 NOT NULL,
    rate_limited bigint DEFAULT 0 NOT NULL,
    bot_blocked bigint DEFAULT 0 NOT NULL,
    top_countries jsonb DEFAULT '{}'::jsonb,
    top_paths jsonb DEFAULT '[]'::jsonb,
    top_ips jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.dashboard_stats_hourly_partitioned (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    hour_bucket timestamp with time zone NOT NULL,
    total_requests bigint DEFAULT 0 NOT NULL,
    status_2xx bigint DEFAULT 0 NOT NULL,
    status_3xx bigint DEFAULT 0 NOT NULL,
    status_4xx bigint DEFAULT 0 NOT NULL,
    status_5xx bigint DEFAULT 0 NOT NULL,
    avg_response_time double precision DEFAULT 0,
    max_response_time double precision DEFAULT 0,
    min_response_time double precision DEFAULT 0,
    p95_response_time double precision DEFAULT 0,
    p99_response_time double precision DEFAULT 0,
    bytes_sent bigint DEFAULT 0 NOT NULL,
    bytes_received bigint DEFAULT 0 NOT NULL,
    waf_blocked bigint DEFAULT 0 NOT NULL,
    waf_detected bigint DEFAULT 0 NOT NULL,
    rate_limited bigint DEFAULT 0 NOT NULL,
    bot_blocked bigint DEFAULT 0 NOT NULL,
    top_countries jsonb DEFAULT '{}'::jsonb,
    top_paths jsonb DEFAULT '[]'::jsonb,
    top_ips jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
)
PARTITION BY RANGE (hour_bucket);
CREATE TABLE IF NOT EXISTS public.dns_providers (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    name character varying(100) NOT NULL,
    provider_type character varying(50) NOT NULL,
    credentials jsonb DEFAULT '{}'::jsonb NOT NULL,
    is_default boolean DEFAULT false NOT NULL,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);
COMMENT ON TABLE public.dns_providers IS 'Stores DNS provider API credentials for ACME DNS-01 challenges';
COMMENT ON COLUMN public.dns_providers.provider_type IS 'DNS provider type: cloudflare, route53, manual, etc.';
COMMENT ON COLUMN public.dns_providers.credentials IS 'Encrypted JSON containing API tokens/keys';
CREATE TABLE IF NOT EXISTS public.exploit_block_rules (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    category character varying(50) NOT NULL,
    name character varying(100) NOT NULL,
    pattern text NOT NULL,
    pattern_type character varying(20) DEFAULT 'query_string'::character varying NOT NULL,
    description text,
    severity character varying(20) DEFAULT 'warning'::character varying,
    enabled boolean DEFAULT true,
    is_system boolean DEFAULT true,
    sort_order integer DEFAULT 0,
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP,
    updated_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE public.exploit_block_rules IS 'Database-managed exploit blocking rules (replaces hardcoded block_exploits)';
COMMENT ON COLUMN public.exploit_block_rules.pattern_type IS 'Where to apply the pattern: query_string, request_uri, user_agent, request_method';
COMMENT ON COLUMN public.exploit_block_rules.is_system IS 'System rules cannot be deleted, only disabled';
CREATE TABLE IF NOT EXISTS public.fail2ban_configs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid NOT NULL,
    enabled boolean DEFAULT true,
    max_retries integer DEFAULT 5,
    find_time integer DEFAULT 600,
    ban_time integer DEFAULT 3600,
    fail_codes character varying(100) DEFAULT '401,403,404'::character varying,
    action character varying(20) DEFAULT 'block'::character varying,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.geo_restrictions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid NOT NULL,
    mode character varying(20) DEFAULT 'blacklist'::character varying NOT NULL,
    countries text[] DEFAULT '{}'::text[] NOT NULL,
    enabled boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    allowed_ips text[] DEFAULT '{}'::text[],
    challenge_mode boolean DEFAULT false,
    blocked_cloud_providers text[] DEFAULT '{}'::text[],
    challenge_cloud_providers boolean DEFAULT false,
    allow_search_bots_cloud_providers boolean DEFAULT false,
    allow_private_ips boolean DEFAULT true,
    allow_search_bots boolean DEFAULT false,
    CONSTRAINT geo_restrictions_mode_check CHECK (((mode)::text = ANY ((ARRAY['whitelist'::character varying, 'blacklist'::character varying])::text[])))
);
COMMENT ON COLUMN public.geo_restrictions.allowed_ips IS 'IP addresses or CIDR ranges that bypass geo restrictions (priority override)';
COMMENT ON COLUMN public.geo_restrictions.challenge_cloud_providers IS 'If true, show challenge (CAPTCHA) instead of blocking cloud provider IPs';
CREATE TABLE IF NOT EXISTS public.geoip_update_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    status character varying(20) DEFAULT 'pending'::character varying NOT NULL,
    trigger_type character varying(20) DEFAULT 'manual'::character varying NOT NULL,
    started_at timestamp with time zone DEFAULT now(),
    completed_at timestamp with time zone,
    duration_ms integer,
    database_version character varying(50),
    country_db_size bigint,
    asn_db_size bigint,
    error_message text,
    created_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.global_exploit_rule_exclusions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id uuid NOT NULL,
    reason text,
    disabled_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE public.global_exploit_rule_exclusions IS 'Global rule exclusions applying to all hosts';
CREATE TABLE IF NOT EXISTS public.global_settings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    worker_processes integer DEFAULT 0 NOT NULL,
    worker_connections integer DEFAULT 1024 NOT NULL,
    worker_rlimit_nofile integer,
    multi_accept boolean DEFAULT true NOT NULL,
    use_epoll boolean DEFAULT true NOT NULL,
    sendfile boolean DEFAULT true NOT NULL,
    tcp_nopush boolean DEFAULT true NOT NULL,
    tcp_nodelay boolean DEFAULT true NOT NULL,
    keepalive_timeout integer DEFAULT 65 NOT NULL,
    keepalive_requests integer DEFAULT 100 NOT NULL,
    types_hash_max_size integer DEFAULT 2048 NOT NULL,
    server_tokens boolean DEFAULT false NOT NULL,
    client_body_buffer_size character varying(20) DEFAULT '16k'::character varying NOT NULL,
    client_header_buffer_size character varying(20) DEFAULT '1k'::character varying NOT NULL,
    client_max_body_size character varying(20) DEFAULT '100m'::character varying NOT NULL,
    large_client_header_buffers character varying(20) DEFAULT '4 8k'::character varying NOT NULL,
    client_body_timeout integer DEFAULT 60 NOT NULL,
    client_header_timeout integer DEFAULT 60 NOT NULL,
    send_timeout integer DEFAULT 60 NOT NULL,
    proxy_connect_timeout integer DEFAULT 60 NOT NULL,
    proxy_send_timeout integer DEFAULT 60 NOT NULL,
    proxy_read_timeout integer DEFAULT 60 NOT NULL,
    gzip_enabled boolean DEFAULT true NOT NULL,
    gzip_vary boolean DEFAULT true NOT NULL,
    gzip_proxied character varying(50) DEFAULT 'any'::character varying NOT NULL,
    gzip_comp_level integer DEFAULT 6 NOT NULL,
    gzip_buffers character varying(20) DEFAULT '16 8k'::character varying NOT NULL,
    gzip_http_version character varying(10) DEFAULT '1.1'::character varying NOT NULL,
    gzip_min_length integer DEFAULT 256 NOT NULL,
    gzip_types text DEFAULT 'text/plain text/css text/xml text/javascript application/json application/javascript application/xml application/xml+rss application/x-javascript image/svg+xml'::text NOT NULL,
    ssl_protocols character varying(100) DEFAULT 'TLSv1.2 TLSv1.3'::character varying NOT NULL,
    ssl_ciphers text DEFAULT 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384'::text NOT NULL,
    ssl_prefer_server_ciphers boolean DEFAULT true NOT NULL,
    ssl_session_cache character varying(50) DEFAULT 'shared:SSL:10m'::character varying NOT NULL,
    ssl_session_timeout character varying(20) DEFAULT '1d'::character varying NOT NULL,
    ssl_session_tickets boolean DEFAULT false NOT NULL,
    ssl_stapling boolean DEFAULT true NOT NULL,
    ssl_stapling_verify boolean DEFAULT true NOT NULL,
    access_log_enabled boolean DEFAULT true NOT NULL,
    error_log_level character varying(20) DEFAULT 'warn'::character varying NOT NULL,
    resolver character varying(255) DEFAULT '8.8.8.8 8.8.4.4 valid=300s'::character varying,
    resolver_timeout character varying(20) DEFAULT '5s'::character varying,
    custom_http_config text DEFAULT ''::text,
    custom_stream_config text DEFAULT ''::text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    brotli_enabled boolean DEFAULT false NOT NULL,
    brotli_comp_level integer DEFAULT 6 NOT NULL,
    brotli_types text DEFAULT 'text/plain text/css text/xml text/javascript application/json application/javascript application/xml application/xml+rss image/svg+xml'::text NOT NULL,
    direct_ip_access_action character varying(20) DEFAULT 'allow'::character varying,
    limit_conn_zone_size character varying(10) DEFAULT '10m'::character varying,
    limit_conn_per_ip integer DEFAULT 100,
    limit_conn_enabled boolean DEFAULT false,
    limit_req_zone_size character varying(10) DEFAULT '10m'::character varying,
    limit_req_rate integer DEFAULT 50,
    limit_req_burst integer DEFAULT 100,
    limit_req_enabled boolean DEFAULT false,
    reset_timedout_connection boolean DEFAULT true,
    limit_rate integer DEFAULT 0,
    limit_rate_after character varying(10) DEFAULT '0'::character varying,
    proxy_buffer_size character varying(20) DEFAULT '8k'::character varying NOT NULL,
    proxy_buffers character varying(20) DEFAULT '8 32k'::character varying NOT NULL,
    proxy_busy_buffers_size character varying(20) DEFAULT '128k'::character varying NOT NULL,
    proxy_max_temp_file_size character varying(20) DEFAULT '1024m'::character varying NOT NULL,
    proxy_temp_file_write_size character varying(20) DEFAULT '64k'::character varying NOT NULL,
    open_file_cache_enabled boolean DEFAULT true NOT NULL,
    open_file_cache_max integer DEFAULT 10000 NOT NULL,
    open_file_cache_inactive character varying(20) DEFAULT '60s'::character varying NOT NULL,
    open_file_cache_valid character varying(20) DEFAULT '30s'::character varying NOT NULL,
    open_file_cache_min_uses integer DEFAULT 2 NOT NULL,
    open_file_cache_errors boolean DEFAULT true NOT NULL,
    brotli_static boolean DEFAULT true NOT NULL,
    connection_upgrade_empty character varying(10) DEFAULT ''::character varying NOT NULL,
    brotli_min_length integer DEFAULT 1000 NOT NULL
);
COMMENT ON COLUMN public.global_settings.worker_connections IS 'Maximum number of simultaneous connections per worker (default: 8192)';
COMMENT ON COLUMN public.global_settings.gzip_min_length IS 'Minimum response size to apply gzip compression (bytes)';
COMMENT ON COLUMN public.global_settings.proxy_buffer_size IS 'Size of the buffer used for the first part of response from upstream';
COMMENT ON COLUMN public.global_settings.proxy_buffers IS 'Number and size of buffers for proxied responses (e.g., "8 32k")';
COMMENT ON COLUMN public.global_settings.open_file_cache_enabled IS 'Enable file descriptor caching for better static file performance';
COMMENT ON COLUMN public.global_settings.brotli_static IS 'Serve pre-compressed .br files if available';
COMMENT ON COLUMN public.global_settings.brotli_min_length IS 'Minimum response size to apply Brotli compression (bytes)';
CREATE TABLE IF NOT EXISTS public.global_uri_blocks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    enabled boolean DEFAULT true,
    rules jsonb DEFAULT '[]'::jsonb,
    exception_ips text[] DEFAULT '{}'::text[],
    allow_private_ips boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.global_waf_policy_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id character varying(20) NOT NULL,
    rule_category character varying(255),
    rule_description text,
    action character varying(20) NOT NULL,
    reason text,
    changed_by character varying(255),
    created_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.global_waf_rule_exclusions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    rule_id character varying(20) NOT NULL,
    rule_category character varying(255),
    rule_description text,
    reason text,
    disabled_by character varying(255),
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.host_exploit_rule_exclusions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid NOT NULL,
    rule_id uuid NOT NULL,
    reason text,
    disabled_by character varying(100),
    created_at timestamp with time zone DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE public.host_exploit_rule_exclusions IS 'Per-host rule exclusions';
CREATE TABLE IF NOT EXISTS public.ip_ban_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    event_type character varying(10) NOT NULL,
    ip_address character varying(45) NOT NULL,
    proxy_host_id uuid,
    domain_name character varying(255),
    reason text,
    source character varying(50) NOT NULL,
    ban_duration integer,
    expires_at timestamp with time zone,
    is_permanent boolean DEFAULT false,
    is_auto boolean DEFAULT false,
    fail_count integer,
    user_id uuid,
    user_email character varying(255),
    metadata jsonb,
    created_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.log_settings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    retention_days integer DEFAULT 30 NOT NULL,
    max_logs_per_type bigint,
    auto_cleanup_enabled boolean DEFAULT true NOT NULL,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    system_log_retention_days integer DEFAULT 7 NOT NULL,
    enable_docker_logs boolean DEFAULT true NOT NULL,
    filter_health_checks boolean DEFAULT true NOT NULL
);
CREATE TABLE IF NOT EXISTS public.login_attempts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    ip_address character varying(45) NOT NULL,
    username character varying(255),
    success boolean DEFAULT false NOT NULL,
    attempted_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    log_type public.log_type NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    host text,
    client_ip inet,
    request_method text,
    request_uri text,
    request_protocol text,
    status_code integer,
    body_bytes_sent bigint,
    request_time numeric(10,6),
    upstream_response_time numeric(10,6),
    http_referer text,
    http_user_agent text,
    http_x_forwarded_for text,
    severity public.log_severity,
    error_message text,
    rule_id integer,
    rule_message text,
    rule_severity text,
    rule_data text,
    attack_type text,
    action_taken text,
    proxy_host_id uuid,
    raw_log text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    geo_country text,
    geo_country_code character varying(2),
    geo_city text,
    geo_asn text,
    geo_org text,
    block_reason public.block_reason DEFAULT 'none'::public.block_reason,
    bot_category text,
    exploit_rule character varying(50)
);
COMMENT ON COLUMN public.logs.geo_country IS 'Country name from GeoIP lookup';
COMMENT ON COLUMN public.logs.geo_country_code IS 'ISO country code (2 letters)';
COMMENT ON COLUMN public.logs.geo_city IS 'City name from GeoIP lookup';
COMMENT ON COLUMN public.logs.geo_asn IS 'Autonomous System Number';
COMMENT ON COLUMN public.logs.geo_org IS 'Organization/ISP name from ASN lookup';
COMMENT ON COLUMN public.logs.exploit_rule IS 'Specific exploit block rule ID (e.g., SQLI-001, RFI-001, VCS-001)';
CREATE TABLE IF NOT EXISTS public.logs_partitioned (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    log_type public.log_type NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    host text,
    client_ip inet,
    request_method text,
    request_uri text,
    request_protocol text,
    status_code integer,
    body_bytes_sent bigint,
    request_time numeric(10,6),
    upstream_response_time numeric(10,6),
    http_referer text,
    http_user_agent text,
    http_x_forwarded_for text,
    severity public.log_severity,
    error_message text,
    rule_id integer,
    rule_message text,
    rule_severity text,
    rule_data text,
    attack_type text,
    action_taken text,
    proxy_host_id uuid,
    raw_log text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    geo_country text,
    geo_country_code character varying(2),
    geo_city text,
    geo_asn text,
    geo_org text,
    block_reason public.block_reason DEFAULT 'none'::public.block_reason,
    bot_category text,
    exploit_rule character varying(50)
)
PARTITION BY RANGE (created_at);
COMMENT ON COLUMN public.logs_partitioned.exploit_rule IS 'Specific exploit block rule ID (e.g., SQLI-001, RFI-001, VCS-001)';
CREATE TABLE IF NOT EXISTS public.logs_p2025_12 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    log_type public.log_type NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    host text,
    client_ip inet,
    request_method text,
    request_uri text,
    request_protocol text,
    status_code integer,
    body_bytes_sent bigint,
    request_time numeric(10,6),
    upstream_response_time numeric(10,6),
    http_referer text,
    http_user_agent text,
    http_x_forwarded_for text,
    severity public.log_severity,
    error_message text,
    rule_id integer,
    rule_message text,
    rule_severity text,
    rule_data text,
    attack_type text,
    action_taken text,
    proxy_host_id uuid,
    raw_log text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    geo_country text,
    geo_country_code character varying(2),
    geo_city text,
    geo_asn text,
    geo_org text,
    block_reason public.block_reason DEFAULT 'none'::public.block_reason,
    bot_category text,
    exploit_rule character varying(50)
);
CREATE TABLE IF NOT EXISTS public.logs_p2026_01 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    log_type public.log_type NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    host text,
    client_ip inet,
    request_method text,
    request_uri text,
    request_protocol text,
    status_code integer,
    body_bytes_sent bigint,
    request_time numeric(10,6),
    upstream_response_time numeric(10,6),
    http_referer text,
    http_user_agent text,
    http_x_forwarded_for text,
    severity public.log_severity,
    error_message text,
    rule_id integer,
    rule_message text,
    rule_severity text,
    rule_data text,
    attack_type text,
    action_taken text,
    proxy_host_id uuid,
    raw_log text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    geo_country text,
    geo_country_code character varying(2),
    geo_city text,
    geo_asn text,
    geo_org text,
    block_reason public.block_reason DEFAULT 'none'::public.block_reason,
    bot_category text,
    exploit_rule character varying(50)
);
CREATE TABLE IF NOT EXISTS public.logs_p2026_02 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    log_type public.log_type NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    host text,
    client_ip inet,
    request_method text,
    request_uri text,
    request_protocol text,
    status_code integer,
    body_bytes_sent bigint,
    request_time numeric(10,6),
    upstream_response_time numeric(10,6),
    http_referer text,
    http_user_agent text,
    http_x_forwarded_for text,
    severity public.log_severity,
    error_message text,
    rule_id integer,
    rule_message text,
    rule_severity text,
    rule_data text,
    attack_type text,
    action_taken text,
    proxy_host_id uuid,
    raw_log text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    geo_country text,
    geo_country_code character varying(2),
    geo_city text,
    geo_asn text,
    geo_org text,
    block_reason public.block_reason DEFAULT 'none'::public.block_reason,
    bot_category text,
    exploit_rule character varying(50)
);
CREATE TABLE IF NOT EXISTS public.logs_p2026_03 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    log_type public.log_type NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    host text,
    client_ip inet,
    request_method text,
    request_uri text,
    request_protocol text,
    status_code integer,
    body_bytes_sent bigint,
    request_time numeric(10,6),
    upstream_response_time numeric(10,6),
    http_referer text,
    http_user_agent text,
    http_x_forwarded_for text,
    severity public.log_severity,
    error_message text,
    rule_id integer,
    rule_message text,
    rule_severity text,
    rule_data text,
    attack_type text,
    action_taken text,
    proxy_host_id uuid,
    raw_log text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    geo_country text,
    geo_country_code character varying(2),
    geo_city text,
    geo_asn text,
    geo_org text,
    block_reason public.block_reason DEFAULT 'none'::public.block_reason,
    bot_category text,
    exploit_rule character varying(50)
);
CREATE TABLE IF NOT EXISTS public.logs_p_default (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    log_type public.log_type NOT NULL,
    "timestamp" timestamp with time zone DEFAULT now() NOT NULL,
    host text,
    client_ip inet,
    request_method text,
    request_uri text,
    request_protocol text,
    status_code integer,
    body_bytes_sent bigint,
    request_time numeric(10,6),
    upstream_response_time numeric(10,6),
    http_referer text,
    http_user_agent text,
    http_x_forwarded_for text,
    severity public.log_severity,
    error_message text,
    rule_id integer,
    rule_message text,
    rule_severity text,
    rule_data text,
    attack_type text,
    action_taken text,
    proxy_host_id uuid,
    raw_log text,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    geo_country text,
    geo_country_code character varying(2),
    geo_city text,
    geo_asn text,
    geo_org text,
    block_reason public.block_reason DEFAULT 'none'::public.block_reason,
    bot_category text,
    exploit_rule character varying(50)
);
CREATE OR REPLACE VIEW public.logs_unified AS
 SELECT logs.id,
    logs.log_type,
    logs."timestamp",
    logs.host,
    logs.client_ip,
    logs.geo_country,
    logs.geo_country_code,
    logs.geo_city,
    logs.geo_asn,
    logs.geo_org,
    logs.request_method,
    logs.request_uri,
    logs.request_protocol,
    logs.status_code,
    logs.body_bytes_sent,
    logs.request_time,
    logs.upstream_response_time,
    logs.http_referer,
    logs.http_user_agent,
    logs.http_x_forwarded_for,
    logs.severity,
    logs.error_message,
    logs.rule_id,
    logs.rule_message,
    logs.rule_severity,
    logs.rule_data,
    logs.attack_type,
    logs.action_taken,
    logs.block_reason,
    logs.bot_category,
    logs.proxy_host_id,
    logs.raw_log,
    logs.created_at
   FROM public.logs
UNION ALL
 SELECT logs_partitioned.id,
    logs_partitioned.log_type,
    logs_partitioned."timestamp",
    logs_partitioned.host,
    logs_partitioned.client_ip,
    logs_partitioned.geo_country,
    logs_partitioned.geo_country_code,
    logs_partitioned.geo_city,
    logs_partitioned.geo_asn,
    logs_partitioned.geo_org,
    logs_partitioned.request_method,
    logs_partitioned.request_uri,
    logs_partitioned.request_protocol,
    logs_partitioned.status_code,
    logs_partitioned.body_bytes_sent,
    logs_partitioned.request_time,
    logs_partitioned.upstream_response_time,
    logs_partitioned.http_referer,
    logs_partitioned.http_user_agent,
    logs_partitioned.http_x_forwarded_for,
    logs_partitioned.severity,
    logs_partitioned.error_message,
    logs_partitioned.rule_id,
    logs_partitioned.rule_message,
    logs_partitioned.rule_severity,
    logs_partitioned.rule_data,
    logs_partitioned.attack_type,
    logs_partitioned.action_taken,
    logs_partitioned.block_reason,
    logs_partitioned.bot_category,
    logs_partitioned.proxy_host_id,
    logs_partitioned.raw_log,
    logs_partitioned.created_at
   FROM public.logs_partitioned;
CREATE TABLE IF NOT EXISTS public.proxy_hosts (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    domain_names text[] NOT NULL,
    forward_scheme character varying(10) DEFAULT 'http'::character varying NOT NULL,
    forward_host character varying(255) NOT NULL,
    forward_port integer DEFAULT 80 NOT NULL,
    ssl_enabled boolean DEFAULT false NOT NULL,
    ssl_force_https boolean DEFAULT false NOT NULL,
    ssl_http2 boolean DEFAULT true NOT NULL,
    certificate_id uuid,
    allow_websocket_upgrade boolean DEFAULT true NOT NULL,
    cache_enabled boolean DEFAULT false NOT NULL,
    cache_static_only boolean DEFAULT true NOT NULL,
    cache_ttl character varying(20) DEFAULT '7d'::character varying NOT NULL,
    block_exploits boolean DEFAULT true NOT NULL,
    custom_locations jsonb DEFAULT '[]'::jsonb,
    advanced_config text DEFAULT ''::text,
    waf_enabled boolean DEFAULT false NOT NULL,
    waf_mode character varying(20) DEFAULT 'detection'::character varying,
    access_list_id uuid,
    enabled boolean DEFAULT true NOT NULL,
    meta jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    ssl_http3 boolean DEFAULT false NOT NULL,
    rate_limit_enabled boolean DEFAULT false,
    fail2ban_enabled boolean DEFAULT false,
    bot_filter_enabled boolean DEFAULT false,
    security_headers_enabled boolean DEFAULT false,
    waf_paranoia_level integer DEFAULT 1,
    waf_anomaly_threshold integer DEFAULT 5,
    block_exploits_exceptions text DEFAULT ''::text,
    CONSTRAINT chk_waf_anomaly_threshold CHECK (((waf_anomaly_threshold >= 1) AND (waf_anomaly_threshold <= 100))),
    CONSTRAINT chk_waf_paranoia_level CHECK (((waf_paranoia_level >= 1) AND (waf_paranoia_level <= 4)))
);
COMMENT ON TABLE public.proxy_hosts IS 'Stores reverse proxy host configurations';
COMMENT ON COLUMN public.proxy_hosts.domain_names IS 'Array of domain names that this proxy responds to';
COMMENT ON COLUMN public.proxy_hosts.forward_scheme IS 'Protocol to use when forwarding (http/https)';
COMMENT ON COLUMN public.proxy_hosts.forward_host IS 'Target host to forward requests to';
COMMENT ON COLUMN public.proxy_hosts.forward_port IS 'Target port to forward requests to';
COMMENT ON COLUMN public.proxy_hosts.custom_locations IS 'JSON array of custom location blocks';
COMMENT ON COLUMN public.proxy_hosts.advanced_config IS 'Raw nginx config to append to server block';
COMMENT ON COLUMN public.proxy_hosts.ssl_http3 IS 'Enable HTTP/3 (QUIC) support for this proxy host';
COMMENT ON COLUMN public.proxy_hosts.waf_paranoia_level IS 'OWASP CRS paranoia level (1-4). Higher = more rules, more false positives';
COMMENT ON COLUMN public.proxy_hosts.waf_anomaly_threshold IS 'Anomaly score threshold for blocking. Lower = stricter';
COMMENT ON COLUMN public.proxy_hosts.block_exploits_exceptions IS 'Newline-separated regex patterns for URI paths that bypass RFI/exploit blocking. Example: ^/wp-json/';
COMMENT ON COLUMN public.proxy_hosts.cache_static_only IS 'Only cache static assets (js, css, images, fonts) - excludes API paths';
COMMENT ON COLUMN public.proxy_hosts.cache_ttl IS 'Cache duration for static assets (e.g., 1h, 7d, 30m)';
CREATE TABLE IF NOT EXISTS public.rate_limits (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid NOT NULL,
    enabled boolean DEFAULT true,
    requests_per_second integer DEFAULT 10,
    burst_size integer DEFAULT 20,
    zone_size character varying(10) DEFAULT '10m'::character varying,
    limit_by character varying(20) DEFAULT 'ip'::character varying,
    limit_response integer DEFAULT 429,
    whitelist_ips text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.redirect_hosts (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    domain_names text[] DEFAULT '{}'::text[] NOT NULL,
    forward_scheme character varying(10) DEFAULT 'auto'::character varying NOT NULL,
    forward_domain_name character varying(255) NOT NULL,
    forward_path character varying(1024) DEFAULT ''::character varying,
    preserve_path boolean DEFAULT true,
    redirect_code integer DEFAULT 301,
    ssl_enabled boolean DEFAULT false,
    certificate_id uuid,
    ssl_force_https boolean DEFAULT true,
    enabled boolean DEFAULT true,
    block_exploits boolean DEFAULT false,
    meta jsonb DEFAULT '{}'::jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    CONSTRAINT redirect_hosts_redirect_code_check CHECK ((redirect_code = ANY (ARRAY[301, 302, 307, 308])))
);
CREATE TABLE IF NOT EXISTS public.schema_migrations (
    version character varying(255) NOT NULL,
    applied_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.security_headers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid NOT NULL,
    enabled boolean DEFAULT true,
    hsts_enabled boolean DEFAULT true,
    hsts_max_age integer DEFAULT 31536000,
    hsts_include_subdomains boolean DEFAULT true,
    hsts_preload boolean DEFAULT false,
    x_frame_options character varying(100) DEFAULT 'SAMEORIGIN'::character varying,
    x_content_type_options boolean DEFAULT true,
    x_xss_protection boolean DEFAULT true,
    referrer_policy character varying(50) DEFAULT 'strict-origin-when-cross-origin'::character varying,
    content_security_policy text,
    permissions_policy text,
    custom_headers jsonb,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.settings (
    key character varying(255) NOT NULL,
    value jsonb NOT NULL,
    updated_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.stats_hourly_p2025_12 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    hour_bucket timestamp with time zone NOT NULL,
    total_requests bigint DEFAULT 0 NOT NULL,
    status_2xx bigint DEFAULT 0 NOT NULL,
    status_3xx bigint DEFAULT 0 NOT NULL,
    status_4xx bigint DEFAULT 0 NOT NULL,
    status_5xx bigint DEFAULT 0 NOT NULL,
    avg_response_time double precision DEFAULT 0,
    max_response_time double precision DEFAULT 0,
    min_response_time double precision DEFAULT 0,
    p95_response_time double precision DEFAULT 0,
    p99_response_time double precision DEFAULT 0,
    bytes_sent bigint DEFAULT 0 NOT NULL,
    bytes_received bigint DEFAULT 0 NOT NULL,
    waf_blocked bigint DEFAULT 0 NOT NULL,
    waf_detected bigint DEFAULT 0 NOT NULL,
    rate_limited bigint DEFAULT 0 NOT NULL,
    bot_blocked bigint DEFAULT 0 NOT NULL,
    top_countries jsonb DEFAULT '{}'::jsonb,
    top_paths jsonb DEFAULT '[]'::jsonb,
    top_ips jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.stats_hourly_p2026_01 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    hour_bucket timestamp with time zone NOT NULL,
    total_requests bigint DEFAULT 0 NOT NULL,
    status_2xx bigint DEFAULT 0 NOT NULL,
    status_3xx bigint DEFAULT 0 NOT NULL,
    status_4xx bigint DEFAULT 0 NOT NULL,
    status_5xx bigint DEFAULT 0 NOT NULL,
    avg_response_time double precision DEFAULT 0,
    max_response_time double precision DEFAULT 0,
    min_response_time double precision DEFAULT 0,
    p95_response_time double precision DEFAULT 0,
    p99_response_time double precision DEFAULT 0,
    bytes_sent bigint DEFAULT 0 NOT NULL,
    bytes_received bigint DEFAULT 0 NOT NULL,
    waf_blocked bigint DEFAULT 0 NOT NULL,
    waf_detected bigint DEFAULT 0 NOT NULL,
    rate_limited bigint DEFAULT 0 NOT NULL,
    bot_blocked bigint DEFAULT 0 NOT NULL,
    top_countries jsonb DEFAULT '{}'::jsonb,
    top_paths jsonb DEFAULT '[]'::jsonb,
    top_ips jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.stats_hourly_p2026_02 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    hour_bucket timestamp with time zone NOT NULL,
    total_requests bigint DEFAULT 0 NOT NULL,
    status_2xx bigint DEFAULT 0 NOT NULL,
    status_3xx bigint DEFAULT 0 NOT NULL,
    status_4xx bigint DEFAULT 0 NOT NULL,
    status_5xx bigint DEFAULT 0 NOT NULL,
    avg_response_time double precision DEFAULT 0,
    max_response_time double precision DEFAULT 0,
    min_response_time double precision DEFAULT 0,
    p95_response_time double precision DEFAULT 0,
    p99_response_time double precision DEFAULT 0,
    bytes_sent bigint DEFAULT 0 NOT NULL,
    bytes_received bigint DEFAULT 0 NOT NULL,
    waf_blocked bigint DEFAULT 0 NOT NULL,
    waf_detected bigint DEFAULT 0 NOT NULL,
    rate_limited bigint DEFAULT 0 NOT NULL,
    bot_blocked bigint DEFAULT 0 NOT NULL,
    top_countries jsonb DEFAULT '{}'::jsonb,
    top_paths jsonb DEFAULT '[]'::jsonb,
    top_ips jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.stats_hourly_p2026_03 (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    hour_bucket timestamp with time zone NOT NULL,
    total_requests bigint DEFAULT 0 NOT NULL,
    status_2xx bigint DEFAULT 0 NOT NULL,
    status_3xx bigint DEFAULT 0 NOT NULL,
    status_4xx bigint DEFAULT 0 NOT NULL,
    status_5xx bigint DEFAULT 0 NOT NULL,
    avg_response_time double precision DEFAULT 0,
    max_response_time double precision DEFAULT 0,
    min_response_time double precision DEFAULT 0,
    p95_response_time double precision DEFAULT 0,
    p99_response_time double precision DEFAULT 0,
    bytes_sent bigint DEFAULT 0 NOT NULL,
    bytes_received bigint DEFAULT 0 NOT NULL,
    waf_blocked bigint DEFAULT 0 NOT NULL,
    waf_detected bigint DEFAULT 0 NOT NULL,
    rate_limited bigint DEFAULT 0 NOT NULL,
    bot_blocked bigint DEFAULT 0 NOT NULL,
    top_countries jsonb DEFAULT '{}'::jsonb,
    top_paths jsonb DEFAULT '[]'::jsonb,
    top_ips jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.stats_hourly_p_default (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    hour_bucket timestamp with time zone NOT NULL,
    total_requests bigint DEFAULT 0 NOT NULL,
    status_2xx bigint DEFAULT 0 NOT NULL,
    status_3xx bigint DEFAULT 0 NOT NULL,
    status_4xx bigint DEFAULT 0 NOT NULL,
    status_5xx bigint DEFAULT 0 NOT NULL,
    avg_response_time double precision DEFAULT 0,
    max_response_time double precision DEFAULT 0,
    min_response_time double precision DEFAULT 0,
    p95_response_time double precision DEFAULT 0,
    p99_response_time double precision DEFAULT 0,
    bytes_sent bigint DEFAULT 0 NOT NULL,
    bytes_received bigint DEFAULT 0 NOT NULL,
    waf_blocked bigint DEFAULT 0 NOT NULL,
    waf_detected bigint DEFAULT 0 NOT NULL,
    rate_limited bigint DEFAULT 0 NOT NULL,
    bot_blocked bigint DEFAULT 0 NOT NULL,
    top_countries jsonb DEFAULT '{}'::jsonb,
    top_paths jsonb DEFAULT '[]'::jsonb,
    top_ips jsonb DEFAULT '[]'::jsonb,
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.system_health (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    recorded_at timestamp with time zone DEFAULT now() NOT NULL,
    nginx_status character varying(20) DEFAULT 'unknown'::character varying NOT NULL,
    nginx_workers integer DEFAULT 0,
    nginx_connections_active integer DEFAULT 0,
    nginx_connections_reading integer DEFAULT 0,
    nginx_connections_writing integer DEFAULT 0,
    nginx_connections_waiting integer DEFAULT 0,
    db_status character varying(20) DEFAULT 'unknown'::character varying NOT NULL,
    db_connections integer DEFAULT 0,
    cpu_usage double precision DEFAULT 0,
    memory_usage double precision DEFAULT 0,
    disk_usage double precision DEFAULT 0,
    certs_total integer DEFAULT 0,
    certs_expiring_soon integer DEFAULT 0,
    certs_expired integer DEFAULT 0,
    upstreams_total integer DEFAULT 0,
    upstreams_healthy integer DEFAULT 0,
    upstreams_unhealthy integer DEFAULT 0,
    memory_total bigint DEFAULT 0,
    memory_used bigint DEFAULT 0,
    disk_total bigint DEFAULT 0,
    disk_used bigint DEFAULT 0,
    disk_path character varying(255) DEFAULT '/'::character varying,
    network_in bigint DEFAULT 0,
    network_out bigint DEFAULT 0,
    uptime_seconds bigint DEFAULT 0,
    hostname character varying(255) DEFAULT ''::character varying,
    os character varying(255) DEFAULT ''::character varying,
    platform character varying(100) DEFAULT ''::character varying,
    kernel_version character varying(255) DEFAULT ''::character varying
);
CREATE TABLE IF NOT EXISTS public.system_logs (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    source public.system_log_source NOT NULL,
    level public.system_log_level DEFAULT 'info'::public.system_log_level NOT NULL,
    message text NOT NULL,
    details jsonb,
    container_name character varying(100),
    component character varying(100),
    created_at timestamp with time zone DEFAULT now() NOT NULL
);
CREATE TABLE IF NOT EXISTS public.system_settings (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    geoip_enabled boolean DEFAULT false NOT NULL,
    maxmind_license_key character varying(255) DEFAULT ''::character varying,
    maxmind_account_id character varying(100) DEFAULT ''::character varying,
    geoip_auto_update boolean DEFAULT true NOT NULL,
    geoip_update_interval character varying(20) DEFAULT '7d'::character varying NOT NULL,
    geoip_last_updated timestamp with time zone,
    geoip_database_version character varying(100) DEFAULT ''::character varying,
    acme_enabled boolean DEFAULT true NOT NULL,
    acme_email character varying(255) DEFAULT ''::character varying,
    acme_staging boolean DEFAULT false NOT NULL,
    acme_auto_renew boolean DEFAULT true NOT NULL,
    acme_renew_days_before integer DEFAULT 30 NOT NULL,
    acme_dns_provider character varying(50) DEFAULT ''::character varying,
    acme_dns_credentials jsonb DEFAULT '{}'::jsonb,
    notification_email character varying(255) DEFAULT ''::character varying,
    notify_cert_expiry boolean DEFAULT true NOT NULL,
    notify_cert_expiry_days integer DEFAULT 14 NOT NULL,
    notify_security_events boolean DEFAULT true NOT NULL,
    notify_backup_complete boolean DEFAULT false NOT NULL,
    log_retention_days integer DEFAULT 30 NOT NULL,
    stats_retention_days integer DEFAULT 90 NOT NULL,
    backup_retention_count integer DEFAULT 10 NOT NULL,
    auto_backup_enabled boolean DEFAULT false NOT NULL,
    auto_backup_schedule character varying(50) DEFAULT '0 2 * * *'::character varying,
    created_at timestamp with time zone DEFAULT now() NOT NULL,
    updated_at timestamp with time zone DEFAULT now() NOT NULL,
    access_log_retention_days integer DEFAULT 1095 NOT NULL,
    waf_log_retention_days integer DEFAULT 90 NOT NULL,
    error_log_retention_days integer DEFAULT 30 NOT NULL,
    system_log_retention_days integer DEFAULT 30 NOT NULL,
    audit_log_retention_days integer DEFAULT 1095 NOT NULL,
    raw_log_enabled boolean DEFAULT false NOT NULL,
    raw_log_retention_days integer DEFAULT 7 NOT NULL,
    raw_log_max_size_mb integer DEFAULT 100 NOT NULL,
    raw_log_rotate_count integer DEFAULT 5 NOT NULL,
    raw_log_compress_rotated boolean DEFAULT true NOT NULL,
    bot_filter_default_enabled boolean DEFAULT false,
    bot_filter_default_block_bad_bots boolean DEFAULT true,
    bot_filter_default_block_ai_bots boolean DEFAULT false,
    bot_filter_default_allow_search_engines boolean DEFAULT true,
    bot_filter_default_challenge_suspicious boolean DEFAULT false,
    bot_filter_default_custom_blocked_agents text DEFAULT ''::text,
    bot_list_bad_bots text DEFAULT 'AhrefsBot
SemrushBot
DotBot
MJ12bot
BLEXBot
DataForSeoBot
serpstatbot
AspiegelBot
BacklinkCrawler
Exabot
Screaming Frog
MegaIndex
LinkpadBot
Nimbostratus-Bot
TurnitinBot
PetalBot
Seekport Crawler
Bytespider
MauiBot
Sogou web spider
YandexBot
Baiduspider'::text,
    bot_list_ai_bots text DEFAULT 'GPTBot
ChatGPT-User
Claude-Web
ClaudeBot
anthropic-ai
Amazonbot
CCBot
Google-Extended
FacebookBot
PerplexityBot
YouBot
Cohere-ai'::text,
    bot_list_search_engines text DEFAULT 'Googlebot
Bingbot
DuckDuckBot
Slurp
facebot
Twitterbot
LinkedInBot
WhatsApp
TelegramBot
Discordbot
Slackbot
Applebot'::text,
    bot_list_suspicious_clients text DEFAULT 'curl
Wget
libwww-perl
python-requests
Python-urllib
Python-httpx
httpx
aiohttp
Java
Go-http-client
Go-http
http_requester
HttpClient
Apache-HttpClient
okhttp
node-fetch
axios
got
request
fetch
urllib
http.client
requests
scrapy
mechanize
phantom
headless
puppeteer
playwright
selenium
chromedriver
geckodriver'::text,
    bot_filter_default_block_suspicious_clients boolean DEFAULT false,
    waf_auto_ban_enabled boolean DEFAULT false,
    waf_auto_ban_threshold integer DEFAULT 10,
    waf_auto_ban_window integer DEFAULT 300,
    waf_auto_ban_duration integer DEFAULT 3600,
    direct_ip_access_action character varying(20) DEFAULT 'allow'::character varying,
    system_logs_enabled boolean DEFAULT true NOT NULL,
    system_logs_levels jsonb DEFAULT '{"npm-guard-db": "warn", "npm-guard-ui": "warn", "npm-guard-api": "info", "npm-guard-proxy": "info"}'::jsonb,
    system_logs_exclude_patterns text[] DEFAULT ARRAY['/health'::text, '/nginx_status'::text, '/.well-known/'::text, 'HEAD /'::text],
    system_logs_stdout_excluded text[] DEFAULT ARRAY['npm-guard-proxy'::text],
    ui_font_family character varying(50) DEFAULT 'system'::character varying,
    global_block_exploits_exceptions text DEFAULT '^/wp-json/
^/api/v1/challenge/
^/wp-admin/admin-ajax.php'::text
);
COMMENT ON COLUMN public.system_settings.access_log_retention_days IS 'Retention period for access logs in days (default: 3 years)';
COMMENT ON COLUMN public.system_settings.waf_log_retention_days IS 'Retention period for WAF/ModSecurity logs in days (default: 3 months)';
COMMENT ON COLUMN public.system_settings.error_log_retention_days IS 'Retention period for error logs in days (default: 1 month)';
COMMENT ON COLUMN public.system_settings.system_log_retention_days IS 'Retention period for system logs in days (default: 1 month)';
COMMENT ON COLUMN public.system_settings.audit_log_retention_days IS 'Retention period for admin audit logs in days (default: 3 years)';
COMMENT ON COLUMN public.system_settings.raw_log_enabled IS 'Enable raw nginx log file storage (in addition to database logging)';
COMMENT ON COLUMN public.system_settings.raw_log_retention_days IS 'How many days to keep rotated raw log files (default: 7 days)';
COMMENT ON COLUMN public.system_settings.raw_log_max_size_mb IS 'Maximum size of each log file before rotation in MB (default: 100MB)';
COMMENT ON COLUMN public.system_settings.raw_log_rotate_count IS 'Number of rotated log files to keep (default: 5)';
COMMENT ON COLUMN public.system_settings.raw_log_compress_rotated IS 'Compress rotated log files with gzip (default: true)';
COMMENT ON COLUMN public.system_settings.global_block_exploits_exceptions IS 'Global regex patterns for URI paths that bypass RFI/exploit blocking (one per line). Applied to all hosts with block_exploits enabled.';
CREATE TABLE IF NOT EXISTS public.upstream_servers (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    upstream_id uuid NOT NULL,
    address character varying(255) NOT NULL,
    port integer DEFAULT 80,
    weight integer DEFAULT 1,
    max_fails integer DEFAULT 3,
    fail_timeout integer DEFAULT 30,
    is_backup boolean DEFAULT false,
    is_down boolean DEFAULT false,
    is_healthy boolean DEFAULT true,
    last_check_at timestamp with time zone,
    last_error text,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.upstreams (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid NOT NULL,
    name character varying(255) NOT NULL,
    servers jsonb DEFAULT '[]'::jsonb NOT NULL,
    load_balance character varying(20) DEFAULT 'round_robin'::character varying,
    health_check_enabled boolean DEFAULT false,
    health_check_interval integer DEFAULT 30,
    health_check_timeout integer DEFAULT 5,
    health_check_path character varying(255) DEFAULT '/'::character varying,
    health_check_expected_status integer DEFAULT 200,
    keepalive integer DEFAULT 32,
    is_healthy boolean DEFAULT true,
    last_check_at timestamp with time zone,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.uri_blocks (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid NOT NULL,
    enabled boolean DEFAULT true,
    rules jsonb DEFAULT '[]'::jsonb,
    exception_ips text[] DEFAULT '{}'::text[],
    allow_private_ips boolean DEFAULT true,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.users (
    id uuid DEFAULT public.uuid_generate_v4() NOT NULL,
    email character varying(255) NOT NULL,
    password_hash character varying(255) NOT NULL,
    name character varying(255),
    role character varying(50) DEFAULT 'user'::character varying,
    created_at timestamp with time zone DEFAULT now(),
    updated_at timestamp with time zone DEFAULT now(),
    username character varying(255) NOT NULL,
    is_initial_setup boolean DEFAULT true NOT NULL,
    last_login_at timestamp with time zone,
    last_login_ip character varying(45),
    login_count integer DEFAULT 0 NOT NULL,
    totp_secret character varying(255),
    totp_enabled boolean DEFAULT false NOT NULL,
    totp_verified_at timestamp with time zone,
    backup_codes text[],
    language character varying(10) DEFAULT 'ko'::character varying,
    font_family character varying(100) DEFAULT 'system'::character varying
);
CREATE TABLE IF NOT EXISTS public.waf_policy_history (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid NOT NULL,
    rule_id integer NOT NULL,
    rule_category character varying(100),
    rule_description text,
    action character varying(20) NOT NULL,
    reason text,
    changed_by character varying(255),
    created_at timestamp with time zone DEFAULT now()
);
COMMENT ON TABLE public.waf_policy_history IS 'Audit log for WAF policy changes';
COMMENT ON COLUMN public.waf_policy_history.action IS 'disabled: rule was disabled, enabled: rule was re-enabled';
CREATE TABLE IF NOT EXISTS public.waf_rule_change_events (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    rule_id character varying(20) NOT NULL,
    action character varying(20) NOT NULL,
    rule_category character varying(255),
    rule_description text,
    reason text,
    changed_by character varying(255),
    created_at timestamp with time zone DEFAULT now()
);
CREATE TABLE IF NOT EXISTS public.waf_rule_exclusions (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid NOT NULL,
    rule_id integer NOT NULL,
    rule_category character varying(100),
    rule_description text,
    reason text,
    disabled_by character varying(255),
    created_at timestamp with time zone DEFAULT now()
);
COMMENT ON TABLE public.waf_rule_exclusions IS 'Per-host WAF rule exclusions for OWASP CRS rules';
COMMENT ON COLUMN public.waf_rule_exclusions.rule_id IS 'OWASP CRS rule ID (e.g., 941100)';
COMMENT ON COLUMN public.waf_rule_exclusions.rule_category IS 'Rule category like XSS, SQLI, RCE, etc.';
CREATE TABLE IF NOT EXISTS public.waf_rule_snapshot_details (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    snapshot_id uuid NOT NULL,
    rule_id character varying(20) NOT NULL,
    rule_category character varying(255),
    rule_description text,
    is_disabled boolean DEFAULT false,
    reason text
);
CREATE TABLE IF NOT EXISTS public.waf_rule_snapshots (
    id uuid DEFAULT gen_random_uuid() NOT NULL,
    proxy_host_id uuid,
    version_number integer NOT NULL,
    snapshot_name character varying(255),
    rule_engine character varying(20),
    paranoia_level integer,
    anomaly_threshold integer,
    total_rules integer DEFAULT 0,
    disabled_rules integer DEFAULT 0,
    change_description text,
    created_by character varying(255),
    created_at timestamp with time zone DEFAULT now()
);
DO $$ BEGIN ALTER TABLE ONLY public.logs_partitioned ATTACH PARTITION public.logs_p2025_12 FOR VALUES FROM ('2025-12-01 00:00:00+00') TO ('2026-01-01 00:00:00+00'); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.logs_partitioned ATTACH PARTITION public.logs_p2026_01 FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2026-02-01 00:00:00+00'); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.logs_partitioned ATTACH PARTITION public.logs_p2026_02 FOR VALUES FROM ('2026-02-01 00:00:00+00') TO ('2026-03-01 00:00:00+00'); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.logs_partitioned ATTACH PARTITION public.logs_p2026_03 FOR VALUES FROM ('2026-03-01 00:00:00+00') TO ('2026-04-01 00:00:00+00'); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.logs_partitioned ATTACH PARTITION public.logs_p_default DEFAULT; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.dashboard_stats_hourly_partitioned ATTACH PARTITION public.stats_hourly_p2025_12 FOR VALUES FROM ('2025-12-01 00:00:00+00') TO ('2026-01-01 00:00:00+00'); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.dashboard_stats_hourly_partitioned ATTACH PARTITION public.stats_hourly_p2026_01 FOR VALUES FROM ('2026-01-01 00:00:00+00') TO ('2026-02-01 00:00:00+00'); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.dashboard_stats_hourly_partitioned ATTACH PARTITION public.stats_hourly_p2026_02 FOR VALUES FROM ('2026-02-01 00:00:00+00') TO ('2026-03-01 00:00:00+00'); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.dashboard_stats_hourly_partitioned ATTACH PARTITION public.stats_hourly_p2026_03 FOR VALUES FROM ('2026-03-01 00:00:00+00') TO ('2026-04-01 00:00:00+00'); EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER TABLE ONLY public.dashboard_stats_hourly_partitioned ATTACH PARTITION public.stats_hourly_p_default DEFAULT; EXCEPTION WHEN OTHERS THEN NULL; END $$;
ALTER TABLE ONLY public.access_list_items
    ADD CONSTRAINT access_list_items_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.access_lists
    ADD CONSTRAINT access_lists_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.api_token_usage
    ADD CONSTRAINT api_token_usage_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_token_hash_key UNIQUE (token_hash);
ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.backups
    ADD CONSTRAINT backups_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.banned_ips
    ADD CONSTRAINT banned_ips_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.bot_filters
    ADD CONSTRAINT bot_filters_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.bot_filters
    ADD CONSTRAINT bot_filters_proxy_host_id_key UNIQUE (proxy_host_id);
ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.certificate_history
    ADD CONSTRAINT certificate_history_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.challenge_configs
    ADD CONSTRAINT challenge_configs_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.challenge_configs
    ADD CONSTRAINT challenge_configs_proxy_host_id_key UNIQUE (proxy_host_id);
ALTER TABLE ONLY public.challenge_logs
    ADD CONSTRAINT challenge_logs_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.challenge_tokens
    ADD CONSTRAINT challenge_tokens_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.cloud_providers
    ADD CONSTRAINT cloud_providers_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.cloud_providers
    ADD CONSTRAINT cloud_providers_slug_key UNIQUE (slug);
ALTER TABLE ONLY public.dashboard_stats_daily
    ADD CONSTRAINT dashboard_stats_daily_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.dashboard_stats_daily
    ADD CONSTRAINT dashboard_stats_daily_proxy_host_id_day_bucket_key UNIQUE (proxy_host_id, day_bucket);
ALTER TABLE ONLY public.dashboard_stats_hourly_partitioned
    ADD CONSTRAINT dashboard_stats_hourly_partitioned_pkey PRIMARY KEY (id, hour_bucket);
ALTER TABLE ONLY public.dashboard_stats_hourly
    ADD CONSTRAINT dashboard_stats_hourly_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.dashboard_stats_hourly
    ADD CONSTRAINT dashboard_stats_hourly_proxy_host_id_hour_bucket_key UNIQUE (proxy_host_id, hour_bucket);
ALTER TABLE ONLY public.dns_providers
    ADD CONSTRAINT dns_providers_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.exploit_block_rules
    ADD CONSTRAINT exploit_block_rules_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.fail2ban_configs
    ADD CONSTRAINT fail2ban_configs_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.fail2ban_configs
    ADD CONSTRAINT fail2ban_configs_proxy_host_id_key UNIQUE (proxy_host_id);
ALTER TABLE ONLY public.geo_restrictions
    ADD CONSTRAINT geo_restrictions_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.geo_restrictions
    ADD CONSTRAINT geo_restrictions_proxy_host_id_key UNIQUE (proxy_host_id);
ALTER TABLE ONLY public.geoip_update_history
    ADD CONSTRAINT geoip_update_history_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.global_exploit_rule_exclusions
    ADD CONSTRAINT global_exploit_rule_exclusions_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.global_exploit_rule_exclusions
    ADD CONSTRAINT global_exploit_rule_exclusions_rule_id_key UNIQUE (rule_id);
ALTER TABLE ONLY public.global_settings
    ADD CONSTRAINT global_settings_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.global_uri_blocks
    ADD CONSTRAINT global_uri_blocks_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.global_waf_policy_history
    ADD CONSTRAINT global_waf_policy_history_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.global_waf_rule_exclusions
    ADD CONSTRAINT global_waf_rule_exclusions_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.global_waf_rule_exclusions
    ADD CONSTRAINT global_waf_rule_exclusions_rule_id_key UNIQUE (rule_id);
ALTER TABLE ONLY public.host_exploit_rule_exclusions
    ADD CONSTRAINT host_exploit_rule_exclusions_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.host_exploit_rule_exclusions
    ADD CONSTRAINT host_exploit_rule_exclusions_proxy_host_id_rule_id_key UNIQUE (proxy_host_id, rule_id);
ALTER TABLE ONLY public.ip_ban_history
    ADD CONSTRAINT ip_ban_history_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.log_settings
    ADD CONSTRAINT log_settings_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.login_attempts
    ADD CONSTRAINT login_attempts_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.logs_partitioned
    ADD CONSTRAINT logs_partitioned_pkey PRIMARY KEY (id, created_at);
ALTER TABLE ONLY public.logs_p2025_12
    ADD CONSTRAINT logs_p2025_12_pkey PRIMARY KEY (id, created_at);
ALTER TABLE ONLY public.logs_p2026_01
    ADD CONSTRAINT logs_p2026_01_pkey PRIMARY KEY (id, created_at);
ALTER TABLE ONLY public.logs_p2026_02
    ADD CONSTRAINT logs_p2026_02_pkey PRIMARY KEY (id, created_at);
ALTER TABLE ONLY public.logs_p2026_03
    ADD CONSTRAINT logs_p2026_03_pkey PRIMARY KEY (id, created_at);
ALTER TABLE ONLY public.logs_p_default
    ADD CONSTRAINT logs_p_default_pkey PRIMARY KEY (id, created_at);
ALTER TABLE ONLY public.logs
    ADD CONSTRAINT logs_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.proxy_hosts
    ADD CONSTRAINT proxy_hosts_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.rate_limits
    ADD CONSTRAINT rate_limits_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.rate_limits
    ADD CONSTRAINT rate_limits_proxy_host_id_key UNIQUE (proxy_host_id);
ALTER TABLE ONLY public.redirect_hosts
    ADD CONSTRAINT redirect_hosts_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.schema_migrations
    ADD CONSTRAINT schema_migrations_pkey PRIMARY KEY (version);
ALTER TABLE ONLY public.security_headers
    ADD CONSTRAINT security_headers_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.security_headers
    ADD CONSTRAINT security_headers_proxy_host_id_key UNIQUE (proxy_host_id);
ALTER TABLE ONLY public.settings
    ADD CONSTRAINT settings_pkey PRIMARY KEY (key);
ALTER TABLE ONLY public.stats_hourly_p2025_12
    ADD CONSTRAINT stats_hourly_p2025_12_pkey PRIMARY KEY (id, hour_bucket);
ALTER TABLE ONLY public.stats_hourly_p2026_01
    ADD CONSTRAINT stats_hourly_p2026_01_pkey PRIMARY KEY (id, hour_bucket);
ALTER TABLE ONLY public.stats_hourly_p2026_02
    ADD CONSTRAINT stats_hourly_p2026_02_pkey PRIMARY KEY (id, hour_bucket);
ALTER TABLE ONLY public.stats_hourly_p2026_03
    ADD CONSTRAINT stats_hourly_p2026_03_pkey PRIMARY KEY (id, hour_bucket);
ALTER TABLE ONLY public.stats_hourly_p_default
    ADD CONSTRAINT stats_hourly_p_default_pkey PRIMARY KEY (id, hour_bucket);
ALTER TABLE ONLY public.system_health
    ADD CONSTRAINT system_health_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.system_logs
    ADD CONSTRAINT system_logs_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.system_settings
    ADD CONSTRAINT system_settings_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.upstream_servers
    ADD CONSTRAINT upstream_servers_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.upstreams
    ADD CONSTRAINT upstreams_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.upstreams
    ADD CONSTRAINT upstreams_proxy_host_id_key UNIQUE (proxy_host_id);
ALTER TABLE ONLY public.uri_blocks
    ADD CONSTRAINT uri_blocks_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_email_key UNIQUE (email);
ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.waf_policy_history
    ADD CONSTRAINT waf_policy_history_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.waf_rule_change_events
    ADD CONSTRAINT waf_rule_change_events_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.waf_rule_exclusions
    ADD CONSTRAINT waf_rule_exclusions_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.waf_rule_exclusions
    ADD CONSTRAINT waf_rule_exclusions_proxy_host_id_rule_id_key UNIQUE (proxy_host_id, rule_id);
ALTER TABLE ONLY public.waf_rule_snapshot_details
    ADD CONSTRAINT waf_rule_snapshot_details_pkey PRIMARY KEY (id);
ALTER TABLE ONLY public.waf_rule_snapshots
    ADD CONSTRAINT waf_rule_snapshots_pkey PRIMARY KEY (id);
CREATE INDEX IF NOT EXISTS idx_access_list_items_list_id ON public.access_list_items USING btree (access_list_id);
CREATE INDEX IF NOT EXISTS idx_api_token_usage_created_at ON public.api_token_usage USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_api_token_usage_token_id ON public.api_token_usage USING btree (token_id);
CREATE INDEX IF NOT EXISTS idx_api_tokens_is_active ON public.api_tokens USING btree (is_active) WHERE (is_active = true);
CREATE INDEX IF NOT EXISTS idx_api_tokens_token_hash ON public.api_tokens USING btree (token_hash);
CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON public.api_tokens USING btree (user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action ON public.audit_logs USING btree (action);
CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON public.audit_logs USING btree (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_resource_type ON public.audit_logs USING btree (resource_type);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_created ON public.audit_logs USING btree (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user_id ON public.audit_logs USING btree (user_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_expires_at ON public.auth_sessions USING btree (expires_at);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_token_hash ON public.auth_sessions USING btree (token_hash);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_user_id ON public.auth_sessions USING btree (user_id);
CREATE INDEX IF NOT EXISTS idx_backups_created ON public.backups USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_banned_ips_auto ON public.banned_ips USING btree (is_auto_banned, expires_at);
CREATE INDEX IF NOT EXISTS idx_banned_ips_expires ON public.banned_ips USING btree (expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_banned_ips_ip_global_unique ON public.banned_ips USING btree (ip_address) WHERE (proxy_host_id IS NULL);
CREATE UNIQUE INDEX IF NOT EXISTS idx_banned_ips_ip_host_unique ON public.banned_ips USING btree (ip_address, proxy_host_id) WHERE (proxy_host_id IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_banned_ips_lookup ON public.banned_ips USING btree (ip_address, expires_at, is_permanent);
CREATE INDEX IF NOT EXISTS idx_banned_ips_proxy_host ON public.banned_ips USING btree (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_certificates_auto_renew ON public.certificates USING btree (auto_renew) WHERE (auto_renew = true);
CREATE INDEX IF NOT EXISTS idx_certificates_domain_names ON public.certificates USING gin (domain_names);
CREATE INDEX IF NOT EXISTS idx_certificates_expires_at ON public.certificates USING btree (expires_at);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON public.certificates USING btree (status);
CREATE INDEX IF NOT EXISTS idx_certificate_history_certificate_id ON public.certificate_history USING btree (certificate_id);
CREATE INDEX IF NOT EXISTS idx_certificate_history_created_at ON public.certificate_history USING btree (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_certificate_history_action ON public.certificate_history USING btree (action);
CREATE INDEX IF NOT EXISTS idx_challenge_logs_created ON public.challenge_logs USING btree (created_at);
CREATE INDEX IF NOT EXISTS idx_challenge_logs_ip ON public.challenge_logs USING btree (client_ip);
CREATE INDEX IF NOT EXISTS idx_challenge_logs_proxy_host ON public.challenge_logs USING btree (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_challenge_tokens_expires ON public.challenge_tokens USING btree (expires_at);
CREATE INDEX IF NOT EXISTS idx_challenge_tokens_hash ON public.challenge_tokens USING btree (token_hash);
CREATE INDEX IF NOT EXISTS idx_challenge_tokens_ip ON public.challenge_tokens USING btree (client_ip);
CREATE INDEX IF NOT EXISTS idx_challenge_tokens_proxy_host ON public.challenge_tokens USING btree (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_cloud_providers_enabled ON public.cloud_providers USING btree (enabled);
CREATE INDEX IF NOT EXISTS idx_cloud_providers_region ON public.cloud_providers USING btree (region);
CREATE INDEX IF NOT EXISTS idx_cloud_providers_slug ON public.cloud_providers USING btree (slug);
CREATE UNIQUE INDEX IF NOT EXISTS idx_dns_providers_default ON public.dns_providers USING btree (is_default) WHERE (is_default = true);
CREATE INDEX IF NOT EXISTS idx_exploit_rules_category ON public.exploit_block_rules USING btree (category);
CREATE INDEX IF NOT EXISTS idx_exploit_rules_enabled ON public.exploit_block_rules USING btree (enabled);
CREATE INDEX IF NOT EXISTS idx_geo_restrictions_blocked_cloud ON public.geo_restrictions USING gin (blocked_cloud_providers);
CREATE INDEX IF NOT EXISTS idx_geo_restrictions_proxy_host ON public.geo_restrictions USING btree (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_geoip_update_history_created_at ON public.geoip_update_history USING btree (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_geoip_update_history_status ON public.geoip_update_history USING btree (status);
CREATE UNIQUE INDEX IF NOT EXISTS idx_global_uri_blocks_singleton ON public.global_uri_blocks USING btree ((true));
CREATE INDEX IF NOT EXISTS idx_global_waf_policy_history_created_at ON public.global_waf_policy_history USING btree (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_global_waf_policy_history_rule_id ON public.global_waf_policy_history USING btree (rule_id);
CREATE INDEX IF NOT EXISTS idx_global_waf_rule_exclusions_rule_id ON public.global_waf_rule_exclusions USING btree (rule_id);
CREATE INDEX IF NOT EXISTS idx_host_exploit_exclusions_host ON public.host_exploit_rule_exclusions USING btree (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_host_exploit_exclusions_rule ON public.host_exploit_rule_exclusions USING btree (rule_id);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_created_at ON public.ip_ban_history USING btree (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_event_type ON public.ip_ban_history USING btree (event_type);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_ip ON public.ip_ban_history USING btree (ip_address);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_ip_created ON public.ip_ban_history USING btree (ip_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_proxy_host ON public.ip_ban_history USING btree (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_source ON public.ip_ban_history USING btree (source);
CREATE INDEX IF NOT EXISTS idx_ip_ban_history_user ON public.ip_ban_history USING btree (user_id);
CREATE INDEX IF NOT EXISTS idx_login_attempts_ip ON public.login_attempts USING btree (ip_address, attempted_at);
CREATE INDEX IF NOT EXISTS idx_logs_access_timestamp ON public.logs USING btree ("timestamp" DESC) WHERE (log_type = 'access'::public.log_type);
CREATE INDEX IF NOT EXISTS idx_logs_block_reason ON public.logs USING btree (block_reason) WHERE (block_reason <> 'none'::public.block_reason);
CREATE INDEX IF NOT EXISTS idx_logs_block_reason_created ON public.logs USING btree (block_reason, created_at DESC) WHERE ((block_reason IS NOT NULL) AND (block_reason <> 'none'::public.block_reason));
CREATE INDEX IF NOT EXISTS idx_logs_bot_filter ON public.logs USING btree (block_reason, bot_category, "timestamp" DESC) WHERE (block_reason = 'bot_filter'::public.block_reason);
CREATE INDEX IF NOT EXISTS idx_logs_client_ip ON public.logs USING btree (client_ip);
CREATE INDEX IF NOT EXISTS idx_logs_created_at_desc ON public.logs USING btree (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_logs_created_host ON public.logs USING btree (created_at DESC, host) WHERE (host IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_logs_created_ip ON public.logs USING btree (created_at DESC, client_ip) WHERE (client_ip IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_logs_created_status ON public.logs USING btree (created_at DESC, status_code) WHERE (status_code IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_logs_created_type ON public.logs USING btree (created_at DESC, log_type);
CREATE INDEX IF NOT EXISTS idx_logs_exploit_rule ON public.logs USING btree (exploit_rule) WHERE ((exploit_rule IS NOT NULL) AND ((exploit_rule)::text <> '-'::text));
CREATE INDEX IF NOT EXISTS idx_logs_geo_asn ON public.logs USING btree (geo_asn);
CREATE INDEX IF NOT EXISTS idx_logs_geo_country ON public.logs USING btree (geo_country_code, created_at DESC) WHERE (geo_country_code IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_logs_geo_country_code ON public.logs USING btree (geo_country_code);
CREATE INDEX IF NOT EXISTS idx_logs_geo_timestamp ON public.logs USING btree ("timestamp" DESC, geo_country_code) WHERE ((log_type = 'access'::public.log_type) AND (geo_country_code IS NOT NULL));
CREATE INDEX IF NOT EXISTS idx_logs_host ON public.logs USING btree (host);
CREATE INDEX IF NOT EXISTS idx_logs_host_timestamp ON public.logs USING btree (host, "timestamp" DESC);
CREATE INDEX IF NOT EXISTS idx_logs_host_trgm ON public.logs USING gin (host public.gin_trgm_ops) WHERE (host IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_logs_log_type ON public.logs USING btree (log_type);
CREATE INDEX IF NOT EXISTS idx_logs_modsec_created ON public.logs USING btree (created_at DESC) WHERE (log_type = 'modsec'::public.log_type);
CREATE INDEX IF NOT EXISTS idx_logs_part_host ON ONLY public.logs_partitioned USING btree (host);
CREATE INDEX IF NOT EXISTS idx_logs_part_log_type ON ONLY public.logs_partitioned USING btree (log_type);
CREATE INDEX IF NOT EXISTS idx_logs_part_timestamp ON ONLY public.logs_partitioned USING btree ("timestamp" DESC);
CREATE INDEX IF NOT EXISTS idx_logs_part_type_timestamp ON ONLY public.logs_partitioned USING btree (log_type, "timestamp" DESC);
CREATE INDEX IF NOT EXISTS idx_logs_partitioned_exploit_rule ON ONLY public.logs_partitioned USING btree (exploit_rule) WHERE ((exploit_rule IS NOT NULL) AND ((exploit_rule)::text <> '-'::text));
CREATE INDEX IF NOT EXISTS idx_logs_proxy_host_id ON public.logs USING btree (proxy_host_id) WHERE (proxy_host_id IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_logs_request_uri_trgm ON public.logs USING gin (request_uri public.gin_trgm_ops) WHERE (request_uri IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_logs_rule_id ON public.logs USING btree (rule_id) WHERE (rule_id IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_logs_severity ON public.logs USING btree (severity) WHERE (severity IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_logs_status_code ON public.logs USING btree (status_code) WHERE (status_code IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON public.logs USING btree ("timestamp" DESC);
CREATE INDEX IF NOT EXISTS idx_logs_type_timestamp ON public.logs USING btree (log_type, "timestamp" DESC);
CREATE INDEX IF NOT EXISTS idx_proxy_hosts_created_at ON public.proxy_hosts USING btree (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_proxy_hosts_domain_names ON public.proxy_hosts USING gin (domain_names);
CREATE INDEX IF NOT EXISTS idx_proxy_hosts_enabled ON public.proxy_hosts USING btree (enabled);
CREATE INDEX IF NOT EXISTS idx_redirect_hosts_domains ON public.redirect_hosts USING gin (domain_names);
CREATE INDEX IF NOT EXISTS idx_stats_daily_bucket ON public.dashboard_stats_daily USING btree (day_bucket);
CREATE INDEX IF NOT EXISTS idx_stats_daily_host_bucket ON public.dashboard_stats_daily USING btree (proxy_host_id, day_bucket);
CREATE INDEX IF NOT EXISTS idx_stats_hourly_bucket ON public.dashboard_stats_hourly USING btree (hour_bucket);
CREATE INDEX IF NOT EXISTS idx_stats_hourly_host_bucket ON public.dashboard_stats_hourly USING btree (proxy_host_id, hour_bucket);
CREATE INDEX IF NOT EXISTS idx_stats_hourly_part_bucket ON ONLY public.dashboard_stats_hourly_partitioned USING btree (hour_bucket);
CREATE INDEX IF NOT EXISTS idx_stats_hourly_part_host ON ONLY public.dashboard_stats_hourly_partitioned USING btree (proxy_host_id, hour_bucket);
CREATE INDEX IF NOT EXISTS idx_system_health_recorded ON public.system_health USING btree (recorded_at);
CREATE INDEX IF NOT EXISTS idx_system_logs_container ON public.system_logs USING btree (container_name, created_at DESC) WHERE (container_name IS NOT NULL);
CREATE INDEX IF NOT EXISTS idx_system_logs_created ON public.system_logs USING btree (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_logs_level ON public.system_logs USING btree (level);
CREATE INDEX IF NOT EXISTS idx_system_logs_source ON public.system_logs USING btree (source);
CREATE INDEX IF NOT EXISTS idx_system_logs_source_created ON public.system_logs USING btree (source, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_logs_source_level_created ON public.system_logs USING btree (source, level, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_system_settings_updated ON public.system_settings USING btree (updated_at);
CREATE INDEX IF NOT EXISTS idx_upstream_servers_upstream ON public.upstream_servers USING btree (upstream_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_uri_blocks_proxy_host ON public.uri_blocks USING btree (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_users_totp_enabled ON public.users USING btree (totp_enabled) WHERE (totp_enabled = true);
CREATE INDEX IF NOT EXISTS idx_waf_policy_history_proxy_host ON public.waf_policy_history USING btree (proxy_host_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_policy_history_rule ON public.waf_policy_history USING btree (rule_id);
CREATE INDEX IF NOT EXISTS idx_waf_rule_changes_proxy_host ON public.waf_rule_change_events USING btree (proxy_host_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_rule_changes_rule ON public.waf_rule_change_events USING btree (rule_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_rule_exclusions_proxy_host ON public.waf_rule_exclusions USING btree (proxy_host_id);
CREATE INDEX IF NOT EXISTS idx_waf_rule_exclusions_rule_id ON public.waf_rule_exclusions USING btree (rule_id);
CREATE INDEX IF NOT EXISTS idx_waf_snapshot_details_snapshot ON public.waf_rule_snapshot_details USING btree (snapshot_id);
CREATE INDEX IF NOT EXISTS idx_waf_snapshots_created_at ON public.waf_rule_snapshots USING btree (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_waf_snapshots_proxy_host_version ON public.waf_rule_snapshots USING btree (proxy_host_id, version_number DESC);
CREATE INDEX IF NOT EXISTS logs_p2025_12_exploit_rule_idx ON public.logs_p2025_12 USING btree (exploit_rule) WHERE ((exploit_rule IS NOT NULL) AND ((exploit_rule)::text <> '-'::text));
CREATE INDEX IF NOT EXISTS logs_p2025_12_host_idx ON public.logs_p2025_12 USING btree (host);
CREATE INDEX IF NOT EXISTS logs_p2025_12_log_type_idx ON public.logs_p2025_12 USING btree (log_type);
CREATE INDEX IF NOT EXISTS logs_p2025_12_log_type_timestamp_idx ON public.logs_p2025_12 USING btree (log_type, "timestamp" DESC);
CREATE INDEX IF NOT EXISTS logs_p2025_12_timestamp_idx ON public.logs_p2025_12 USING btree ("timestamp" DESC);
CREATE INDEX IF NOT EXISTS logs_p2026_01_exploit_rule_idx ON public.logs_p2026_01 USING btree (exploit_rule) WHERE ((exploit_rule IS NOT NULL) AND ((exploit_rule)::text <> '-'::text));
CREATE INDEX IF NOT EXISTS logs_p2026_01_host_idx ON public.logs_p2026_01 USING btree (host);
CREATE INDEX IF NOT EXISTS logs_p2026_01_log_type_idx ON public.logs_p2026_01 USING btree (log_type);
CREATE INDEX IF NOT EXISTS logs_p2026_01_log_type_timestamp_idx ON public.logs_p2026_01 USING btree (log_type, "timestamp" DESC);
CREATE INDEX IF NOT EXISTS logs_p2026_01_timestamp_idx ON public.logs_p2026_01 USING btree ("timestamp" DESC);
CREATE INDEX IF NOT EXISTS logs_p2026_02_exploit_rule_idx ON public.logs_p2026_02 USING btree (exploit_rule) WHERE ((exploit_rule IS NOT NULL) AND ((exploit_rule)::text <> '-'::text));
CREATE INDEX IF NOT EXISTS logs_p2026_02_host_idx ON public.logs_p2026_02 USING btree (host);
CREATE INDEX IF NOT EXISTS logs_p2026_02_log_type_idx ON public.logs_p2026_02 USING btree (log_type);
CREATE INDEX IF NOT EXISTS logs_p2026_02_log_type_timestamp_idx ON public.logs_p2026_02 USING btree (log_type, "timestamp" DESC);
CREATE INDEX IF NOT EXISTS logs_p2026_02_timestamp_idx ON public.logs_p2026_02 USING btree ("timestamp" DESC);
CREATE INDEX IF NOT EXISTS logs_p2026_03_exploit_rule_idx ON public.logs_p2026_03 USING btree (exploit_rule) WHERE ((exploit_rule IS NOT NULL) AND ((exploit_rule)::text <> '-'::text));
CREATE INDEX IF NOT EXISTS logs_p2026_03_host_idx ON public.logs_p2026_03 USING btree (host);
CREATE INDEX IF NOT EXISTS logs_p2026_03_log_type_idx ON public.logs_p2026_03 USING btree (log_type);
CREATE INDEX IF NOT EXISTS logs_p2026_03_log_type_timestamp_idx ON public.logs_p2026_03 USING btree (log_type, "timestamp" DESC);
CREATE INDEX IF NOT EXISTS logs_p2026_03_timestamp_idx ON public.logs_p2026_03 USING btree ("timestamp" DESC);
CREATE INDEX IF NOT EXISTS logs_p_default_exploit_rule_idx ON public.logs_p_default USING btree (exploit_rule) WHERE ((exploit_rule IS NOT NULL) AND ((exploit_rule)::text <> '-'::text));
CREATE INDEX IF NOT EXISTS logs_p_default_host_idx ON public.logs_p_default USING btree (host);
CREATE INDEX IF NOT EXISTS logs_p_default_log_type_idx ON public.logs_p_default USING btree (log_type);
CREATE INDEX IF NOT EXISTS logs_p_default_log_type_timestamp_idx ON public.logs_p_default USING btree (log_type, "timestamp" DESC);
CREATE INDEX IF NOT EXISTS logs_p_default_timestamp_idx ON public.logs_p_default USING btree ("timestamp" DESC);
CREATE INDEX IF NOT EXISTS stats_hourly_p2025_12_hour_bucket_idx ON public.stats_hourly_p2025_12 USING btree (hour_bucket);
CREATE INDEX IF NOT EXISTS stats_hourly_p2025_12_proxy_host_id_hour_bucket_idx ON public.stats_hourly_p2025_12 USING btree (proxy_host_id, hour_bucket);
CREATE INDEX IF NOT EXISTS stats_hourly_p2026_01_hour_bucket_idx ON public.stats_hourly_p2026_01 USING btree (hour_bucket);
CREATE INDEX IF NOT EXISTS stats_hourly_p2026_01_proxy_host_id_hour_bucket_idx ON public.stats_hourly_p2026_01 USING btree (proxy_host_id, hour_bucket);
CREATE INDEX IF NOT EXISTS stats_hourly_p2026_02_hour_bucket_idx ON public.stats_hourly_p2026_02 USING btree (hour_bucket);
CREATE INDEX IF NOT EXISTS stats_hourly_p2026_02_proxy_host_id_hour_bucket_idx ON public.stats_hourly_p2026_02 USING btree (proxy_host_id, hour_bucket);
CREATE INDEX IF NOT EXISTS stats_hourly_p2026_03_hour_bucket_idx ON public.stats_hourly_p2026_03 USING btree (hour_bucket);
CREATE INDEX IF NOT EXISTS stats_hourly_p2026_03_proxy_host_id_hour_bucket_idx ON public.stats_hourly_p2026_03 USING btree (proxy_host_id, hour_bucket);
CREATE INDEX IF NOT EXISTS stats_hourly_p_default_hour_bucket_idx ON public.stats_hourly_p_default USING btree (hour_bucket);
CREATE INDEX IF NOT EXISTS stats_hourly_p_default_proxy_host_id_hour_bucket_idx ON public.stats_hourly_p_default USING btree (proxy_host_id, hour_bucket);
CREATE UNIQUE INDEX IF NOT EXISTS users_username_key ON public.users USING btree (username);
DO $$ BEGIN ALTER INDEX public.idx_logs_partitioned_exploit_rule ATTACH PARTITION public.logs_p2025_12_exploit_rule_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_host ATTACH PARTITION public.logs_p2025_12_host_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_log_type ATTACH PARTITION public.logs_p2025_12_log_type_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_type_timestamp ATTACH PARTITION public.logs_p2025_12_log_type_timestamp_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.logs_partitioned_pkey ATTACH PARTITION public.logs_p2025_12_pkey; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_timestamp ATTACH PARTITION public.logs_p2025_12_timestamp_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_partitioned_exploit_rule ATTACH PARTITION public.logs_p2026_01_exploit_rule_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_host ATTACH PARTITION public.logs_p2026_01_host_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_log_type ATTACH PARTITION public.logs_p2026_01_log_type_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_type_timestamp ATTACH PARTITION public.logs_p2026_01_log_type_timestamp_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.logs_partitioned_pkey ATTACH PARTITION public.logs_p2026_01_pkey; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_timestamp ATTACH PARTITION public.logs_p2026_01_timestamp_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_partitioned_exploit_rule ATTACH PARTITION public.logs_p2026_02_exploit_rule_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_host ATTACH PARTITION public.logs_p2026_02_host_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_log_type ATTACH PARTITION public.logs_p2026_02_log_type_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_type_timestamp ATTACH PARTITION public.logs_p2026_02_log_type_timestamp_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.logs_partitioned_pkey ATTACH PARTITION public.logs_p2026_02_pkey; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_timestamp ATTACH PARTITION public.logs_p2026_02_timestamp_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_partitioned_exploit_rule ATTACH PARTITION public.logs_p2026_03_exploit_rule_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_host ATTACH PARTITION public.logs_p2026_03_host_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_log_type ATTACH PARTITION public.logs_p2026_03_log_type_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_type_timestamp ATTACH PARTITION public.logs_p2026_03_log_type_timestamp_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.logs_partitioned_pkey ATTACH PARTITION public.logs_p2026_03_pkey; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_timestamp ATTACH PARTITION public.logs_p2026_03_timestamp_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_partitioned_exploit_rule ATTACH PARTITION public.logs_p_default_exploit_rule_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_host ATTACH PARTITION public.logs_p_default_host_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_log_type ATTACH PARTITION public.logs_p_default_log_type_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_type_timestamp ATTACH PARTITION public.logs_p_default_log_type_timestamp_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.logs_partitioned_pkey ATTACH PARTITION public.logs_p_default_pkey; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_logs_part_timestamp ATTACH PARTITION public.logs_p_default_timestamp_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_stats_hourly_part_bucket ATTACH PARTITION public.stats_hourly_p2025_12_hour_bucket_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.dashboard_stats_hourly_partitioned_pkey ATTACH PARTITION public.stats_hourly_p2025_12_pkey; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_stats_hourly_part_host ATTACH PARTITION public.stats_hourly_p2025_12_proxy_host_id_hour_bucket_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_stats_hourly_part_bucket ATTACH PARTITION public.stats_hourly_p2026_01_hour_bucket_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.dashboard_stats_hourly_partitioned_pkey ATTACH PARTITION public.stats_hourly_p2026_01_pkey; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_stats_hourly_part_host ATTACH PARTITION public.stats_hourly_p2026_01_proxy_host_id_hour_bucket_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_stats_hourly_part_bucket ATTACH PARTITION public.stats_hourly_p2026_02_hour_bucket_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.dashboard_stats_hourly_partitioned_pkey ATTACH PARTITION public.stats_hourly_p2026_02_pkey; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_stats_hourly_part_host ATTACH PARTITION public.stats_hourly_p2026_02_proxy_host_id_hour_bucket_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_stats_hourly_part_bucket ATTACH PARTITION public.stats_hourly_p2026_03_hour_bucket_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.dashboard_stats_hourly_partitioned_pkey ATTACH PARTITION public.stats_hourly_p2026_03_pkey; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_stats_hourly_part_host ATTACH PARTITION public.stats_hourly_p2026_03_proxy_host_id_hour_bucket_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_stats_hourly_part_bucket ATTACH PARTITION public.stats_hourly_p_default_hour_bucket_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.dashboard_stats_hourly_partitioned_pkey ATTACH PARTITION public.stats_hourly_p_default_pkey; EXCEPTION WHEN OTHERS THEN NULL; END $$;
DO $$ BEGIN ALTER INDEX public.idx_stats_hourly_part_host ATTACH PARTITION public.stats_hourly_p_default_proxy_host_id_hour_bucket_idx; EXCEPTION WHEN OTHERS THEN NULL; END $$;
CREATE TRIGGER trigger_api_tokens_updated_at BEFORE UPDATE ON public.api_tokens FOR EACH ROW EXECUTE FUNCTION public.update_api_tokens_updated_at();
CREATE TRIGGER trigger_challenge_configs_updated_at BEFORE UPDATE ON public.challenge_configs FOR EACH ROW EXECUTE FUNCTION public.update_challenge_configs_updated_at();
CREATE TRIGGER trigger_cloud_providers_updated_at BEFORE UPDATE ON public.cloud_providers FOR EACH ROW EXECUTE FUNCTION public.update_cloud_providers_updated_at();
CREATE TRIGGER update_certificates_updated_at BEFORE UPDATE ON public.certificates FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_dns_providers_updated_at BEFORE UPDATE ON public.dns_providers FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_global_uri_blocks_updated_at BEFORE UPDATE ON public.global_uri_blocks FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_log_settings_updated_at BEFORE UPDATE ON public.log_settings FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_proxy_hosts_updated_at BEFORE UPDATE ON public.proxy_hosts FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
CREATE TRIGGER update_uri_blocks_updated_at BEFORE UPDATE ON public.uri_blocks FOR EACH ROW EXECUTE FUNCTION public.update_updated_at_column();
ALTER TABLE ONLY public.access_list_items
    ADD CONSTRAINT access_list_items_access_list_id_fkey FOREIGN KEY (access_list_id) REFERENCES public.access_lists(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.api_token_usage
    ADD CONSTRAINT api_token_usage_token_id_fkey FOREIGN KEY (token_id) REFERENCES public.api_tokens(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.api_tokens
    ADD CONSTRAINT api_tokens_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.auth_sessions
    ADD CONSTRAINT auth_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.banned_ips
    ADD CONSTRAINT banned_ips_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.bot_filters
    ADD CONSTRAINT bot_filters_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.certificates
    ADD CONSTRAINT certificates_dns_provider_id_fkey FOREIGN KEY (dns_provider_id) REFERENCES public.dns_providers(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.certificate_history
    ADD CONSTRAINT certificate_history_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.challenge_configs
    ADD CONSTRAINT challenge_configs_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.challenge_logs
    ADD CONSTRAINT challenge_logs_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.challenge_tokens
    ADD CONSTRAINT challenge_tokens_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.dashboard_stats_daily
    ADD CONSTRAINT dashboard_stats_daily_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.dashboard_stats_hourly
    ADD CONSTRAINT dashboard_stats_hourly_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.fail2ban_configs
    ADD CONSTRAINT fail2ban_configs_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.geo_restrictions
    ADD CONSTRAINT geo_restrictions_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.global_exploit_rule_exclusions
    ADD CONSTRAINT global_exploit_rule_exclusions_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.exploit_block_rules(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.host_exploit_rule_exclusions
    ADD CONSTRAINT host_exploit_rule_exclusions_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.host_exploit_rule_exclusions
    ADD CONSTRAINT host_exploit_rule_exclusions_rule_id_fkey FOREIGN KEY (rule_id) REFERENCES public.exploit_block_rules(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.ip_ban_history
    ADD CONSTRAINT ip_ban_history_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.ip_ban_history
    ADD CONSTRAINT ip_ban_history_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.logs
    ADD CONSTRAINT logs_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.proxy_hosts
    ADD CONSTRAINT proxy_hosts_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.rate_limits
    ADD CONSTRAINT rate_limits_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.redirect_hosts
    ADD CONSTRAINT redirect_hosts_certificate_id_fkey FOREIGN KEY (certificate_id) REFERENCES public.certificates(id) ON DELETE SET NULL;
ALTER TABLE ONLY public.security_headers
    ADD CONSTRAINT security_headers_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.upstream_servers
    ADD CONSTRAINT upstream_servers_upstream_id_fkey FOREIGN KEY (upstream_id) REFERENCES public.upstreams(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.upstreams
    ADD CONSTRAINT upstreams_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.uri_blocks
    ADD CONSTRAINT uri_blocks_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.waf_policy_history
    ADD CONSTRAINT waf_policy_history_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.waf_rule_change_events
    ADD CONSTRAINT waf_rule_change_events_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.waf_rule_exclusions
    ADD CONSTRAINT waf_rule_exclusions_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.waf_rule_snapshot_details
    ADD CONSTRAINT waf_rule_snapshot_details_snapshot_id_fkey FOREIGN KEY (snapshot_id) REFERENCES public.waf_rule_snapshots(id) ON DELETE CASCADE;
ALTER TABLE ONLY public.waf_rule_snapshots
    ADD CONSTRAINT waf_rule_snapshots_proxy_host_id_fkey FOREIGN KEY (proxy_host_id) REFERENCES public.proxy_hosts(id) ON DELETE CASCADE;

-- Default data

-- Default admin user (password: admin)
INSERT INTO public.users (id, username, password_hash, role, is_initial_setup, language, font_family)
VALUES ('00000000-0000-0000-0000-000000000001', 'admin', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy', 'admin', true, 'ko', 'system')
ON CONFLICT (id) DO NOTHING;

-- Default system settings
INSERT INTO public.system_settings (id, direct_ip_action, ssl_protocols, ssl_ciphers, ssl_prefer_server_ciphers, ssl_session_cache, ssl_session_timeout, proxy_connect_timeout, proxy_send_timeout, proxy_read_timeout, client_max_body_size, global_block_exploits_exceptions)
VALUES (1, 'allow', 'TLSv1.2 TLSv1.3', 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384', true, 'shared:SSL:50m', '1d', 60, 60, 60, '50m', E'^/wp-json/\n^/api/v1/challenge/')
ON CONFLICT (id) DO NOTHING;

-- Default exploit block rules (system rules)
INSERT INTO public.exploit_block_rules (id, category, name, pattern, pattern_type, description, severity, enabled, is_system, sort_order) VALUES
('4243721e-8f8d-4a2b-8496-0be62d50163f', 'sql_injection', 'SQL Union Select', E'(\\"|''|`)(.*)(union)(.*)(select)(\\"|''|`)', 'query_string', 'Blocks SQL UNION SELECT injection attempts', 'critical', true, true, 1),
('a5cb921c-2c10-475b-8753-a56e2af1e5ba', 'sql_injection', 'SQL Commands', E'(;|\\||`|>|<|\\^|@)', 'query_string', 'Blocks SQL command characters (semicolon, pipe, backtick, redirects)', 'warning', true, true, 2),
('41d1f7bf-9179-44cb-b41a-1685ce88d965', 'sql_injection', 'SQL Keywords', E'\\b(select|insert|update|delete|drop|truncate|alter|create|exec)\\b', 'query_string', 'Blocks common SQL keywords in query strings', 'warning', true, true, 3),
('b890779f-757c-4461-a64a-dce59fb469e3', 'xss', 'Script Tags', '<script', 'query_string', 'Blocks script tag injection', 'critical', true, true, 10),
('27ed45b1-e030-4212-bc34-edc7e13a9695', 'xss', 'Event Handlers', 'on(click|load|error|mouseover|focus|blur|change|submit)=', 'query_string', 'Blocks JavaScript event handler injection', 'critical', true, true, 11),
('aa90285b-2986-46f9-80e6-99946327cd24', 'xss', 'Special Characters', '(;|<|>|"|%0A|%0D|%22|%3C|%3E|%00)', 'query_string', 'Blocks XSS special characters (semicolon, angle brackets, encoded newlines/quotes/null)', 'warning', true, true, 12),
('23b31cc1-0e43-49af-b9c9-4093fd0cbcdc', 'rfi', 'URL Parameter Injection', '[a-zA-Z0-9_]=https?://', 'query_string', 'Blocks URL values in query parameters (RFI)', 'critical', true, true, 20),
('7db3e194-8731-40c1-afaa-b7555c017a3f', 'rfi', 'Path Traversal Sequences', E'[a-zA-Z0-9_]=(\\.\\./)+', 'query_string', 'Blocks path traversal in parameters', 'critical', true, true, 21),
('650c5e4a-c373-4d99-9cac-9e86b55bcb33', 'rfi', 'Directory Traversal', E'\\.\\./', 'query_string', 'Blocks directory traversal patterns', 'warning', true, true, 22),
('f055a131-0596-419f-944a-cb7fa40f5c59', 'scanner', 'Nikto Scanner', 'nikto', 'user_agent', 'Blocks Nikto vulnerability scanner', 'critical', true, true, 30),
('f13159ab-0e9a-45ea-aa4b-03fde63bb3e6', 'scanner', 'SQLMap Tool', 'sqlmap', 'user_agent', 'Blocks SQLMap SQL injection tool', 'critical', true, true, 31),
('a9baaa39-ccd9-4f8a-82c0-e7d85f02cc2f', 'scanner', 'DirBuster', 'dirbuster', 'user_agent', 'Blocks DirBuster directory scanner', 'critical', true, true, 32),
('8208101f-eb91-4b86-8396-f295cd16d04b', 'scanner', 'Nmap Scanner', 'nmap', 'user_agent', 'Blocks Nmap network scanner', 'warning', true, true, 33),
('7efe59af-2d2a-405e-bbe8-951757e72ef4', 'scanner', 'Nessus Scanner', 'nessus', 'user_agent', 'Blocks Nessus vulnerability scanner', 'warning', true, true, 34),
('9a5f6bcb-ceec-47f1-9f8c-dadb815711fa', 'scanner', 'OpenVAS Scanner', 'openvas', 'user_agent', 'Blocks OpenVAS security scanner', 'warning', true, true, 35),
('ab3b4e85-08fd-49fe-b76d-3dc5cdf5a248', 'scanner', 'W3AF Scanner', 'w3af', 'user_agent', 'Blocks W3AF web scanner', 'warning', true, true, 36),
('eb60d9dd-1d53-4a42-b571-cef1d1314d4d', 'scanner', 'Acunetix Scanner', 'acunetix', 'user_agent', 'Blocks Acunetix web scanner', 'warning', true, true, 37),
('86fddcd3-30ca-43d3-bd46-34875e018395', 'scanner', 'Havij Tool', 'havij', 'user_agent', 'Blocks Havij SQL injection tool', 'critical', true, true, 38),
('bd7eeece-8f91-41a6-b06c-1ad69900512d', 'scanner', 'AppScan', 'appscan', 'user_agent', 'Blocks IBM AppScan', 'warning', true, true, 39),
('6ee9b160-9472-4584-9c83-8de7b955a4b5', 'scanner', 'WebScarab', 'webscarab', 'user_agent', 'Blocks WebScarab proxy', 'warning', true, true, 40),
('e78e2ef1-d710-409b-8a44-a03db3999b19', 'scanner', 'WebInspect', 'webinspect', 'user_agent', 'Blocks HP WebInspect', 'warning', true, true, 41),
('8ec83a35-dea8-4f51-9185-37035f0a4501', 'http_method', 'Dangerous Methods', '^(TRACE|TRACK|DEBUG|CONNECT)$', 'request_method', 'Blocks dangerous HTTP methods', 'warning', true, true, 50)
ON CONFLICT (id) DO NOTHING;

-- ============================================================================
-- UPGRADE SECTION: Add new columns for existing installations
-- This section uses ADD COLUMN IF NOT EXISTS to safely add columns
-- that may not exist in older database versions
-- ============================================================================

-- Enum upgrades
ALTER TYPE public.block_reason ADD VALUE IF NOT EXISTS 'cloud_provider_challenge';

-- proxy_hosts table upgrades
ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS cache_static_only boolean DEFAULT true NOT NULL;
ALTER TABLE public.proxy_hosts ADD COLUMN IF NOT EXISTS cache_ttl character varying(20) DEFAULT '7d'::character varying NOT NULL;

-- Add column comments
COMMENT ON COLUMN public.proxy_hosts.cache_static_only IS 'Only cache static assets (js, css, images, fonts) - excludes API paths';
COMMENT ON COLUMN public.proxy_hosts.cache_ttl IS 'Cache duration for static assets (e.g., 1h, 7d, 30m)';
