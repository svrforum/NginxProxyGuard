package nginx

import "nginx-proxy-guard/internal/model"

const proxyHostTemplate = `# nginx-guard generated config
# Proxy Host ID: {{.Host.ID}}
# Domain(s): {{join .Host.DomainNames ", "}}
# WAF: {{if .Host.WAFEnabled}}{{.Host.WAFMode}}{{else}}disabled{{end}}
# HTTP/3: {{if .Host.SSLHTTP3}}enabled{{else}}disabled{{end}}
# Access List: {{if .AccessList}}{{.AccessList.Name}}{{else}}none{{end}}
# Geo Restriction: {{if .GeoRestriction}}{{.GeoRestriction.Mode}} ({{len .GeoRestriction.Countries}} countries){{else}}none{{end}}
# Rate Limit: {{if .RateLimit}}{{if .RateLimit.Enabled}}{{.RateLimit.RequestsPerSecond}}r/s{{else}}disabled{{end}}{{else}}none{{end}}
# Upstream: {{if .Upstream}}{{.Upstream.Name}} ({{.Upstream.LoadBalance}}){{else}}none{{end}}
# Generated at: {{now}}

{{if .RateLimit}}{{if .RateLimit.Enabled}}
# Rate limiting zone definition
limit_req_zone ${{if eq .RateLimit.LimitBy "uri"}}request_uri{{else if eq .RateLimit.LimitBy "ip_uri"}}binary_remote_addr$request_uri{{else}}binary_remote_addr{{end}} zone=rate_{{sanitizeID .Host.ID}}:{{.RateLimit.ZoneSize}} rate={{.RateLimit.RequestsPerSecond}}r/s;
{{end}}{{end}}

{{if .BannedIPs}}
# Banned IPs geo mapping for {{join .Host.DomainNames ", "}}
geo $banned_ip_{{sanitizeID .Host.ID}} {
    default 0;
{{range .BannedIPs}}
    {{.IPAddress}} 1; # {{.Reason}}
{{end}}
}
{{end}}

{{if .BlockedCloudIPRanges}}
# Blocked Cloud Provider IPs geo mapping for {{join .Host.DomainNames ", "}}
geo $blocked_cloud_{{sanitizeID .Host.ID}} {
    default 0;
{{range .BlockedCloudIPRanges}}
    {{.}} 1;
{{end}}
}
{{end}}

{{if .Upstream}}
# Upstream definition for load balancing
upstream {{.Upstream.Name}} {
{{if eq .Upstream.LoadBalance "least_conn"}}
    least_conn;
{{else if eq .Upstream.LoadBalance "ip_hash"}}
    ip_hash;
{{else if eq .Upstream.LoadBalance "random"}}
    random;
{{end}}
{{range .Upstream.Servers}}
    server {{.Address}}:{{.Port}}{{if ne .Weight 1}} weight={{.Weight}}{{end}}{{if ne .MaxFails 0}} max_fails={{.MaxFails}}{{end}}{{if ne .FailTimeout 0}} fail_timeout={{.FailTimeout}}s{{end}}{{if .IsBackup}} backup{{end}}{{if .IsDown}} down{{end}};
{{end}}
{{if .Upstream.Keepalive}}
    keepalive {{.Upstream.Keepalive}};
{{end}}
}
{{end}}

{{if .Host.Enabled}}
server {
    listen 80;
    listen [::]:80;
    server_name {{join .Host.DomainNames " "}};

    # Initialize tracking variables
    set $block_reason_var "-";
    set $bot_category_var "-";
    set $geo_blocked 0;

    # Skip security checks for ACME HTTP-01 Challenge
    set $skip_security_for_acme 0;
    if ($request_uri ~ "^/.well-known/acme-challenge/") {
        set $skip_security_for_acme 1;
    }
    # Also skip for challenge page to prevent redirect loops
    if ($request_uri ~ "^/api/v1/challenge/") {
        set $skip_security_for_acme 1;
    }

    # ACME HTTP-01 Challenge support (bypass all security checks)
    location /.well-known/acme-challenge/ {
        # Allow all access for certificate validation
        allow all;
        root /etc/nginx/acme-challenge;
        try_files $uri =404;
    }

    # Custom error pages for upstream errors
    error_page 502 /error_502.html;
    error_page 503 /error_503.html;
    error_page 504 /error_504.html;
    location = /error_502.html { internal; root /etc/nginx/html; try_files /502.html =502; }
    location = /error_503.html { internal; root /etc/nginx/html; try_files /503.html =503; }
    location = /error_504.html { internal; root /etc/nginx/html; try_files /504.html =504; }

    # Custom error page for security blocks (WAF, block_exploits, geo restriction, bot filter, etc.)
    error_page 403 @blocked;
    location @blocked {
        root /etc/nginx/html;
        default_type text/html;
        try_files /403.html =403;
    }

{{if .GeoRestriction}}{{if .GeoRestriction.Enabled}}{{if not .GeoRestriction.ChallengeMode}}
    # Geo Restriction ({{.GeoRestriction.Mode}}) - Direct Block Mode (processed BEFORE WAF for performance){{if .GeoRestriction.AllowPrivateIPs}} - Private IPs Allowed{{end}}{{if .GeoRestriction.AllowSearchBots}} - Search Bots Allowed{{end}}
{{if .GeoRestriction.AllowSearchBots}}{{if .SearchEnginesList}}
    # Check if request is from a search engine bot (uses dynamic list from system settings)
    set $is_search_bot 0;
    if ($http_user_agent ~* ({{toRegexPattern .SearchEnginesList}})) {
        set $is_search_bot 1;
    }
{{end}}{{end}}
{{if len .GeoRestriction.AllowedIPs}}
    # Priority Allow IPs/CIDRs - bypass geo restriction if matched
    set $geo_allowed_ip 0;
{{range .GeoRestriction.AllowedIPs}}
{{if isCIDR .}}
    if ($remote_addr ~ "{{cidrToNginxPattern .}}") {
        set $geo_allowed_ip 1;
    }
{{else}}
    if ($remote_addr = "{{.}}") {
        set $geo_allowed_ip 1;
    }
{{end}}
{{end}}
    # Apply geo restriction only if not in allowed IPs
    set $geo_block_check "";
{{if eq .GeoRestriction.Mode "whitelist"}}
    if ($geoip2_country_code !~ "^({{join .GeoRestriction.Countries "|"}}{{if .GeoRestriction.AllowPrivateIPs}}|--{{end}})$") {
        set $geo_block_check "Y";
        set $block_reason_var "geo_block";
    }
{{else}}
    if ($geoip2_country_code ~ "^({{join .GeoRestriction.Countries "|"}})$") {
        set $geo_block_check "Y";
        set $block_reason_var "geo_block";
    }
{{if .GeoRestriction.AllowPrivateIPs}}
    # Allow private IPs (geo code "--")
    if ($geoip2_country_code = "--") {
        set $geo_block_check "";
    }
{{end}}
{{end}}
{{if .GeoRestriction.AllowSearchBots}}
    # Allow search engine bots - bypass geo restriction
    if ($is_search_bot = 1) {
        set $geo_block_check "";
        set $block_reason_var "-";
    }
{{end}}
    # Combine checks: block only if geo_allowed_ip=0 AND geo_block_check=Y AND not ACME challenge
    set $geo_final_block "${geo_allowed_ip}${geo_block_check}${skip_security_for_acme}";
    if ($geo_final_block = "0Y0") {
        return 403;
    }
{{else}}
{{if .GeoRestriction.AllowSearchBots}}
    # Allow search engine bots - bypass geo restriction
    set $geo_block_check "";
{{if eq .GeoRestriction.Mode "whitelist"}}
    if ($geoip2_country_code !~ "^({{join .GeoRestriction.Countries "|"}}{{if .GeoRestriction.AllowPrivateIPs}}|--{{end}})$") {
        set $geo_block_check "Y";
        set $block_reason_var "geo_block";
    }
{{else}}
    if ($geoip2_country_code ~ "^({{join .GeoRestriction.Countries "|"}})$") {
        set $geo_block_check "Y";
        set $block_reason_var "geo_block";
    }
{{if .GeoRestriction.AllowPrivateIPs}}
    # Allow private IPs (geo code "--")
    if ($geoip2_country_code = "--") {
        set $geo_block_check "";
    }
{{end}}
{{end}}
    # Allow search bots
    if ($is_search_bot = 1) {
        set $geo_block_check "";
        set $block_reason_var "-";
    }
    # Skip geo block for ACME challenge
    set $geo_block_final "${geo_block_check}${skip_security_for_acme}";
    if ($geo_block_final = "Y0") {
        return 403;
    }
{{else}}
{{if eq .GeoRestriction.Mode "whitelist"}}
    # Check geo restriction (skip for ACME challenge)
    set $geo_direct_block "";
    if ($geoip2_country_code !~ "^({{join .GeoRestriction.Countries "|"}}{{if .GeoRestriction.AllowPrivateIPs}}|--{{end}})$") {
        set $geo_direct_block "Y";
        set $block_reason_var "geo_block";
    }
    set $geo_direct_final "${geo_direct_block}${skip_security_for_acme}";
    if ($geo_direct_final = "Y0") {
        return 403;
    }
{{else}}
    # Check geo restriction (skip for ACME challenge)
    set $geo_direct_block "";
    if ($geoip2_country_code ~ "^({{join .GeoRestriction.Countries "|"}})$") {
        set $geo_direct_block "Y";
        set $block_reason_var "geo_block";
    }
{{if .GeoRestriction.AllowPrivateIPs}}
    # Allow private IPs (geo code "--") - skip block
    if ($geoip2_country_code = "--") {
        set $geo_direct_block "";
        set $block_reason_var "-";
    }
{{end}}
    set $geo_direct_final "${geo_direct_block}${skip_security_for_acme}";
    if ($geo_direct_final = "Y0") {
        return 403;
    }
{{end}}
{{end}}
{{end}}
{{end}}{{end}}{{end}}

{{if .Host.WAFEnabled}}
    # WAF (ModSecurity) - {{.Host.WAFMode}} mode
    # Ensure Host header is set for HTTP/3 requests (uses :authority pseudo-header)
    more_set_input_headers "Host: $host";
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/{{wafConfig .Host}};
{{end}}

{{if .GeoRestriction}}{{if .GeoRestriction.Enabled}}{{if .GeoRestriction.ChallengeMode}}
    # Geo Restriction ({{.GeoRestriction.Mode}}) - Challenge Mode (processed AFTER WAF){{if .GeoRestriction.AllowPrivateIPs}} - Private IPs Allowed{{end}}{{if .GeoRestriction.AllowSearchBots}} - Search Bots Allowed{{end}}
{{if .GeoRestriction.AllowSearchBots}}{{if .SearchEnginesList}}
    # Check if request is from a search engine bot (uses dynamic list from system settings)
    set $is_search_bot 0;
    if ($http_user_agent ~* ({{toRegexPattern .SearchEnginesList}})) {
        set $is_search_bot 1;
    }
{{end}}{{end}}
    # Challenge mode: show CAPTCHA instead of blocking
    set $geo_blocked 0;
{{if eq .GeoRestriction.Mode "whitelist"}}
    if ($geoip2_country_code !~ "^({{join .GeoRestriction.Countries "|"}}{{if .GeoRestriction.AllowPrivateIPs}}|--{{end}})$") {
        set $geo_blocked 1;
        set $block_reason_var "geo_block";
    }
{{else}}
    if ($geoip2_country_code ~ "^({{join .GeoRestriction.Countries "|"}})$") {
        set $geo_blocked 1;
        set $block_reason_var "geo_block";
    }
{{if .GeoRestriction.AllowPrivateIPs}}
    # Allow private IPs (geo code "--")
    if ($geoip2_country_code = "--") {
        set $geo_blocked 0;
    }
{{end}}
{{end}}
{{if len .GeoRestriction.AllowedIPs}}
    # Priority Allow IPs/CIDRs - bypass geo restriction if matched
{{range .GeoRestriction.AllowedIPs}}
{{if isCIDR .}}
    if ($remote_addr ~ "{{cidrToNginxPattern .}}") {
        set $geo_blocked 0;
        set $block_reason_var "-";
    }
{{else}}
    if ($remote_addr = "{{.}}") {
        set $geo_blocked 0;
        set $block_reason_var "-";
    }
{{end}}
{{end}}
{{end}}
{{if .GeoRestriction.AllowSearchBots}}
    # Allow search engine bots - bypass geo challenge
    if ($is_search_bot = 1) {
        set $geo_blocked 0;
        set $block_reason_var "-";
    }
{{end}}
{{end}}{{end}}{{end}}

{{if .AccessList}}{{if .AccessList.Items}}
    # Access List: {{.AccessList.Name}}
    # Note: Access list denials will have block_reason set to access_denied
    set $block_reason_var "access_denied";
{{if .AccessList.SatisfyAny}}    satisfy any;{{end}}
{{range .AccessList.Items}}
    {{.Directive}} {{.Address}};{{if .Description}} # {{.Description}}{{end}}
{{end}}
    deny all;
{{end}}{{end}}

{{if .Host.BlockExploits}}
    # Block common exploits (database-managed rules)
{{if hasExploitRules .ExploitBlockRules}}
    # Query string rules (SQL injection, XSS, etc.) with URI exception handling
{{if hasRulesOfType .ExploitBlockRules "query_string"}}
    set $exploit_qs_block 0;
    set $exploit_qs_rule "-";
{{range filterRulesByPatternType .ExploitBlockRules "query_string"}}
    # {{.Name}} ({{.Category}})
    if ($query_string ~* "{{escapeNginxPattern .Pattern}}") {
        set $exploit_qs_block 1;
        set $exploit_qs_rule "{{.ID}}";
    }
{{end}}
{{if hasMergedExceptions .GlobalBlockExploitsExceptions .Host.BlockExploitsExceptions}}
    # URI exceptions - skip query string blocking for these paths
{{range splitExceptions (mergeExceptions .GlobalBlockExploitsExceptions .Host.BlockExploitsExceptions)}}
    if ($request_uri ~* "{{.}}") {
        set $exploit_qs_block 0;
    }
{{end}}
{{end}}
    if ($exploit_qs_block = 1) {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var $exploit_qs_rule;
        return 403;
    }
{{end}}

    # Request URI rules with RFI exception handling
{{if hasRulesOfType .ExploitBlockRules "request_uri"}}
    set $rfi_block 0;
{{range filterRulesByPatternType .ExploitBlockRules "request_uri"}}
    # {{.Name}} ({{.Category}})
    if ($request_uri ~* "{{escapeNginxPattern .Pattern}}") {
        set $rfi_block 1;
    }
{{end}}
{{if hasMergedExceptions .GlobalBlockExploitsExceptions .Host.BlockExploitsExceptions}}
    # Dynamic exceptions from database (global + host-specific)
{{range splitExceptions (mergeExceptions .GlobalBlockExploitsExceptions .Host.BlockExploitsExceptions)}}
    if ($request_uri ~* "{{.}}") {
        set $rfi_block 0;
    }
{{end}}
{{end}}
    if ($rfi_block = 1) {
        set $block_reason_var "exploit_block";
        return 403;
    }
{{end}}

    # User-agent rules (scanner/tool detection)
{{if hasRulesOfType .ExploitBlockRules "user_agent"}}
{{range filterRulesByPatternType .ExploitBlockRules "user_agent"}}
    # {{.Name}} ({{.Category}})
    if ($http_user_agent ~* "{{escapeNginxPattern .Pattern}}") {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "{{.ID}}";
        set $bot_category_var "scanner";
        return 403;
    }
{{end}}
{{end}}

    # HTTP method rules
{{if hasRulesOfType .ExploitBlockRules "request_method"}}
{{range filterRulesByPatternType .ExploitBlockRules "request_method"}}
    # {{.Name}} ({{.Category}})
    if ($request_method ~* "{{escapeNginxPattern .Pattern}}") {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "{{.ID}}";
        return 405;
    }
{{end}}
{{end}}
{{else}}
    # Fallback: No DB rules found, using hardcoded rules
    # SQL injection attempts in query string
    if ($query_string ~* "union.*select") {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "SQLI-FALLBACK-001";
        return 403;
    }
    if ($query_string ~* "(;|<|>|'|\"|\)|%0A|%0D|%22|%27|%3C|%3E|%00)") {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "SQLI-FALLBACK-002";
        return 403;
    }
    # File injection / path traversal (RFI)
    set $rfi_block 0;
    if ($query_string ~* "[a-zA-Z0-9_]=https?://") {
        set $rfi_block 1;
    }
{{if hasMergedExceptions .GlobalBlockExploitsExceptions .Host.BlockExploitsExceptions}}
{{range splitExceptions (mergeExceptions .GlobalBlockExploitsExceptions .Host.BlockExploitsExceptions)}}
    if ($request_uri ~* "{{.}}") {
        set $rfi_block 0;
    }
{{end}}
{{end}}
    if ($rfi_block = 1) {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "RFI-FALLBACK-001";
        return 403;
    }
    if ($query_string ~* "\.\./") {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "LFI-FALLBACK-001";
        return 403;
    }
    # Block exploit tools and scanners
    if ($http_user_agent ~* (nikto|sqlmap|dirbuster|nmap|nessus|openvas|w3af|acunetix|havij|appscan|webscarab|webinspect)) {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "SCAN-FALLBACK-001";
        set $bot_category_var "scanner";
        return 403;
    }
    # Block suspicious request methods
    if ($request_method !~ ^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$) {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "METHOD-FALLBACK-001";
        return 405;
    }
{{end}}
{{end}}

{{if .BannedIPs}}
    # Banned IPs check
    if ($banned_ip_{{sanitizeID .Host.ID}} = 1) {
        set $block_reason_var "banned_ip";
        return 403;
    }
{{end}}

{{if .BlockedCloudIPRanges}}
    # Blocked Cloud Provider IPs check
    # Skip for ACME challenge and challenge page (prevents redirect loops)
    # Priority Allow IPs bypass cloud provider blocking
    set $is_priority_allow_cloud $skip_security_for_acme;
{{if and .GeoRestriction (len .GeoRestriction.AllowedIPs)}}
{{range .GeoRestriction.AllowedIPs}}
{{if isCIDR .}}
    if ($remote_addr ~ "{{cidrToNginxPattern .}}") {
        set $is_priority_allow_cloud 1;
    }
{{else}}
    if ($remote_addr = "{{.}}") {
        set $is_priority_allow_cloud 1;
    }
{{end}}
{{end}}
{{end}}
{{if .CloudProviderAllowSearchBots}}{{if .SearchEnginesList}}
    # Allow search engine bots to bypass cloud provider blocking
    if ($http_user_agent ~* ({{toRegexPattern .SearchEnginesList}})) {
        set $is_priority_allow_cloud 1;
    }
{{end}}{{end}}
    set $cloud_block_check_{{sanitizeID .Host.ID}} "${blocked_cloud_{{sanitizeID .Host.ID}}}${is_priority_allow_cloud}";
{{if .CloudProviderChallengeMode}}
    # Challenge mode - redirect to challenge page instead of blocking (skip for priority IPs, search bots, and ACME/challenge paths)
    if ($cloud_block_check_{{sanitizeID .Host.ID}} = "10") {
        set $block_reason_var "cloud_provider_challenge";
        return 418; # Use 418 as internal marker for cloud challenge redirect
    }
    error_page 418 = @cloud_challenge;
{{else}}
    # Block mode (skip for priority IPs, search bots, and ACME/challenge paths)
    if ($cloud_block_check_{{sanitizeID .Host.ID}} = "10") {
        set $block_reason_var "cloud_provider_block";
        return 403;
    }
{{end}}
{{end}}

{{if .BotFilter}}{{if .BotFilter.Enabled}}
    # Bot Filter - uses error_page 403 for custom error page
    # Priority Allow IPs bypass all bot filtering
    # Also bypass for ACME challenge
    set $priority_allow $skip_security_for_acme;
{{if and .GeoRestriction (len .GeoRestriction.AllowedIPs)}}
{{range .GeoRestriction.AllowedIPs}}
{{if isCIDR .}}
    if ($remote_addr ~ "{{cidrToNginxPattern .}}") {
        set $priority_allow 1;
    }
{{else}}
    if ($remote_addr = "{{.}}") {
        set $priority_allow 1;
    }
{{end}}
{{end}}
{{end}}
{{if .BotFilter.AllowSearchEngines}}{{if .SearchEnginesList}}
    # Allow search engine bots to bypass bot filter
    if ($http_user_agent ~* ({{toRegexPattern .SearchEnginesList}})) {
        set $priority_allow 1;
    }
{{end}}{{end}}
{{if .BotFilter.BlockBadBots}}{{if .BadBotsList}}
    set $block_bad_bot 0;
    if ($http_user_agent ~* ({{toRegexPattern .BadBotsList}})) {
        set $block_bad_bot 1;
        set $block_reason_var "bot_filter";
        set $bot_category_var "bad_bot";
    }
    # Block only if not in priority allow list
    set $bad_bot_check "${priority_allow}${block_bad_bot}";
    if ($bad_bot_check = "01") {
        return 403;
    }
{{end}}{{end}}
{{if .BotFilter.BlockAIBots}}{{if .AIBotsList}}
    set $block_ai_bot 0;
    if ($http_user_agent ~* ({{toRegexPattern .AIBotsList}})) {
        set $block_ai_bot 1;
        set $block_reason_var "bot_filter";
        set $bot_category_var "ai_bot";
    }
    # Block only if not in priority allow list
    set $ai_bot_check "${priority_allow}${block_ai_bot}";
    if ($ai_bot_check = "01") {
        return 403;
    }
{{end}}{{end}}
{{if .BotFilter.BlockSuspiciousClients}}{{if .SuspiciousClientsList}}
    set $block_suspicious 0;
    if ($http_user_agent ~* ({{toRegexPattern .SuspiciousClientsList}})) {
        set $block_suspicious 1;
        set $block_reason_var "bot_filter";
        set $bot_category_var "suspicious";
    }
    # Block only if not in priority allow list
    set $suspicious_check "${priority_allow}${block_suspicious}";
    if ($suspicious_check = "01") {
        return 403;
    }
{{end}}{{end}}
{{if .BotFilter.CustomBlockedAgents}}
    set $block_custom 0;
    if ($http_user_agent ~* ({{toRegexPattern .BotFilter.CustomBlockedAgents}})) {
        set $block_custom 1;
        set $block_reason_var "bot_filter";
        set $bot_category_var "custom";
    }
    # Block only if not in priority allow list
    set $custom_check "${priority_allow}${block_custom}";
    if ($custom_check = "01") {
        return 403;
    }
{{end}}
{{end}}{{end}}

{{if .RateLimit}}{{if .RateLimit.Enabled}}
    # Rate Limiting
    limit_req zone=rate_{{sanitizeID .Host.ID}} burst={{.RateLimit.BurstSize}} nodelay;
    limit_req_status {{.RateLimit.LimitResponse}};
    error_page {{.RateLimit.LimitResponse}} = @rate_limited;
{{end}}{{end}}

{{if .URIBlock}}{{if .URIBlock.Enabled}}
    # URI Path Blocking
{{range .URIBlock.Rules}}{{if .Enabled}}
    # Block: {{.Description}}
    {{uriLocationDirective .MatchType .Pattern}} {
{{if hasURIBlockExceptionIPs $.URIBlock}}
        # Check exception IPs
        set $uri_block_exception 0;
{{if $.URIBlock.AllowPrivateIPs}}
        # Allow private IPs (10.x, 172.16-31.x, 192.168.x)
        if ($remote_addr ~ "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)") {
            set $uri_block_exception 1;
        }
{{end}}
{{range $.URIBlock.ExceptionIPs}}
{{if isCIDR .}}
        if ($remote_addr ~ "{{cidrToNginxPattern .}}") {
            set $uri_block_exception 1;
        }
{{else}}
        if ($remote_addr = "{{.}}") {
            set $uri_block_exception 1;
        }
{{end}}
{{end}}
        if ($uri_block_exception = 0) {
            set $block_reason_var "uri_block";
            return 403;
        }
        # Pass through to upstream if exception matched
        {{if $.Upstream}}proxy_pass http://{{$.Upstream.Name}};{{else}}proxy_pass {{$.Host.ForwardScheme}}://{{$.Host.ForwardHost}}:{{$.Host.ForwardPort}};{{end}}
        include /etc/nginx/includes/proxy_params.conf;
{{else}}
        set $block_reason_var "uri_block";
        return 403;
{{end}}
    }
{{end}}{{end}}
{{end}}{{end}}

{{if .GeoRestriction}}{{if .GeoRestriction.ChallengeMode}}
    # Challenge validation endpoint (internal)
    location = /_challenge/validate {
        internal;
        proxy_pass http://{{apiHost}}/api/v1/challenge/validate;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Proxy-Host-ID "{{.Host.ID}}";
        proxy_set_header X-Challenge-Token $cookie_ng_challenge;
        proxy_set_header X-Geo-Blocked $geo_blocked;
        # Fast timeout - fail fast if API is down
        proxy_connect_timeout 2s;
        proxy_read_timeout 5s;
    }

    # Challenge page redirect for geo-blocked users
    location = /_challenge/page {
        internal;
        return 302 /api/v1/challenge/page?host={{.Host.ID}}&reason=geo_restriction&return=$scheme://$host$request_uri;
    }

    # API error fallback - allow traffic through when API is down
    location @api_fallback {
        # API is down - allow request to proceed (graceful degradation)
        # Log this event for monitoring
        access_log /etc/nginx/logs/access_raw.log main;
        {{if .Upstream}}proxy_pass http://{{.Upstream.Name}};{{else}}proxy_pass {{.Host.ForwardScheme}}://{{.Host.ForwardHost}}:{{.Host.ForwardPort}};{{end}}
        include /etc/nginx/includes/proxy_params.conf;
    }
{{end}}{{end}}

{{if .Host.SSLEnabled}}
    # Redirect HTTP to HTTPS
    {{if .Host.SSLForceHTTPS}}
    location / {
        return 301 https://$host$request_uri;
    }
    {{else}}
    location / {
{{if .GeoRestriction}}{{if .GeoRestriction.ChallengeMode}}
        # Check challenge token for geo-blocked users (skip for search bots)
        set $challenge_check 0;
        if ($geo_blocked = 1) {
            set $challenge_check 1;
        }
{{if .GeoRestriction.AllowSearchBots}}
        # Search bots bypass challenge completely
        if ($is_search_bot = 1) {
            set $challenge_check 0;
        }
{{end}}
        set $challenge_check_final $challenge_check;
        if ($cookie_ng_challenge = "") {
            set $challenge_check_final "${challenge_check}1";
        }
        if ($challenge_check_final = 11) {
            # No token, redirect to challenge page
            return 302 /api/v1/challenge/page?host={{.Host.ID}}&reason=geo_restriction&return=$scheme://$host$request_uri;
        }
        # Validate existing token for geo-blocked users
        # Note: API returns 200 for search bots, so they won't be redirected
        auth_request /_challenge/validate;
        error_page 401 = @challenge_redirect;
        error_page 500 502 503 504 = @api_fallback;
{{end}}{{end}}
        {{if .Upstream}}proxy_pass http://{{.Upstream.Name}};{{else}}proxy_pass {{.Host.ForwardScheme}}://{{.Host.ForwardHost}}:{{.Host.ForwardPort}};{{end}}
        include /etc/nginx/includes/proxy_params.conf;
        {{if .GlobalSettings}}
        # Global proxy settings
        {{if gt .GlobalSettings.ProxyConnectTimeout 0}}proxy_connect_timeout {{.GlobalSettings.ProxyConnectTimeout}}s;{{end}}
        {{if gt .GlobalSettings.ProxySendTimeout 0}}proxy_send_timeout {{.GlobalSettings.ProxySendTimeout}}s;{{end}}
        {{if gt .GlobalSettings.ProxyReadTimeout 0}}proxy_read_timeout {{.GlobalSettings.ProxyReadTimeout}}s;{{end}}
        {{if gt .GlobalSettings.ClientBodyTimeout 0}}client_body_timeout {{.GlobalSettings.ClientBodyTimeout}}s;{{end}}
        {{if gt .GlobalSettings.SendTimeout 0}}send_timeout {{.GlobalSettings.SendTimeout}}s;{{end}}
        {{if .GlobalSettings.ClientMaxBodySize}}client_max_body_size {{.GlobalSettings.ClientMaxBodySize}};{{end}}
        # Proxy buffer settings (from Global Settings)
        {{if .GlobalSettings.ProxyBufferSize}}proxy_buffer_size {{.GlobalSettings.ProxyBufferSize}};{{end}}
        {{if .GlobalSettings.ProxyBuffers}}proxy_buffers {{.GlobalSettings.ProxyBuffers}};{{end}}
        {{if .GlobalSettings.ProxyBusyBuffersSize}}proxy_busy_buffers_size {{.GlobalSettings.ProxyBusyBuffersSize}};{{end}}
        {{end}}
        {{if .Host.AllowWebsocketUpgrade}}
        # WebSocket support (proxy_http_version already set in proxy_params.conf)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        {{end}}
        {{if .Host.CacheEnabled}}
        # Caching
        {{if .Host.CacheStaticOnly}}
        # Static assets only - bypass cache for API and dynamic content
        set $cache_bypass 1;
        if ($request_uri ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|webp|avif|mp4|webm|pdf)$) {
            set $cache_bypass 0;
        }
        proxy_no_cache $cache_bypass;
        proxy_cache_bypass $cache_bypass $http_pragma $http_authorization;
        {{else}}
        # All content except API paths
        set $cache_bypass 0;
        if ($request_uri ~* ^/api/) {
            set $cache_bypass 1;
        }
        proxy_no_cache $cache_bypass;
        proxy_cache_bypass $cache_bypass $http_pragma $http_authorization;
        {{end}}
        proxy_cache proxy_cache;
        proxy_cache_key $scheme$host$request_uri;
        proxy_cache_valid 200 301 302 {{if .Host.CacheTTL}}{{.Host.CacheTTL}}{{else}}1h{{end}};
        proxy_cache_use_stale error timeout http_500 http_502 http_503 http_504;
        add_header X-Cache-Status $upstream_cache_status always;
        {{end}}
    }
{{if .GeoRestriction}}{{if .GeoRestriction.ChallengeMode}}
    location @challenge_redirect {
        return 302 /api/v1/challenge/page?host={{.Host.ID}}&reason=geo_restriction&return=$scheme://$host$request_uri;
    }
{{end}}{{end}}
    {{end}}
{{else}}
    location / {
{{if .GeoRestriction}}{{if .GeoRestriction.ChallengeMode}}
        # Check challenge token for geo-blocked users (skip for search bots)
        set $challenge_check 0;
        if ($geo_blocked = 1) {
            set $challenge_check 1;
        }
{{if .GeoRestriction.AllowSearchBots}}
        # Search bots bypass challenge completely
        if ($is_search_bot = 1) {
            set $challenge_check 0;
        }
{{end}}
        set $challenge_check_final $challenge_check;
        if ($cookie_ng_challenge = "") {
            set $challenge_check_final "${challenge_check}1";
        }
        if ($challenge_check_final = 11) {
            # No token, redirect to challenge page
            return 302 /api/v1/challenge/page?host={{.Host.ID}}&reason=geo_restriction&return=$scheme://$host$request_uri;
        }
        # Validate existing token for geo-blocked users
        # Note: API returns 200 for search bots, so they won't be redirected
        auth_request /_challenge/validate;
        error_page 401 = @challenge_redirect;
        error_page 500 502 503 504 = @api_fallback;
{{end}}{{end}}
        {{if .Upstream}}proxy_pass http://{{.Upstream.Name}};{{else}}proxy_pass {{.Host.ForwardScheme}}://{{.Host.ForwardHost}}:{{.Host.ForwardPort}};{{end}}
        include /etc/nginx/includes/proxy_params.conf;
        {{if .GlobalSettings}}
        # Global proxy settings
        {{if gt .GlobalSettings.ProxyConnectTimeout 0}}proxy_connect_timeout {{.GlobalSettings.ProxyConnectTimeout}}s;{{end}}
        {{if gt .GlobalSettings.ProxySendTimeout 0}}proxy_send_timeout {{.GlobalSettings.ProxySendTimeout}}s;{{end}}
        {{if gt .GlobalSettings.ProxyReadTimeout 0}}proxy_read_timeout {{.GlobalSettings.ProxyReadTimeout}}s;{{end}}
        {{if gt .GlobalSettings.ClientBodyTimeout 0}}client_body_timeout {{.GlobalSettings.ClientBodyTimeout}}s;{{end}}
        {{if gt .GlobalSettings.SendTimeout 0}}send_timeout {{.GlobalSettings.SendTimeout}}s;{{end}}
        {{if .GlobalSettings.ClientMaxBodySize}}client_max_body_size {{.GlobalSettings.ClientMaxBodySize}};{{end}}
        # Proxy buffer settings (from Global Settings)
        {{if .GlobalSettings.ProxyBufferSize}}proxy_buffer_size {{.GlobalSettings.ProxyBufferSize}};{{end}}
        {{if .GlobalSettings.ProxyBuffers}}proxy_buffers {{.GlobalSettings.ProxyBuffers}};{{end}}
        {{if .GlobalSettings.ProxyBusyBuffersSize}}proxy_busy_buffers_size {{.GlobalSettings.ProxyBusyBuffersSize}};{{end}}
        {{end}}
        {{if .Host.AllowWebsocketUpgrade}}
        # WebSocket support (proxy_http_version already set in proxy_params.conf)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        {{end}}
        {{if .Host.CacheEnabled}}
        # Caching
        {{if .Host.CacheStaticOnly}}
        # Static assets only - bypass cache for API and dynamic content
        set $cache_bypass 1;
        if ($request_uri ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|webp|avif|mp4|webm|pdf)$) {
            set $cache_bypass 0;
        }
        proxy_no_cache $cache_bypass;
        proxy_cache_bypass $cache_bypass $http_pragma $http_authorization;
        {{else}}
        # All content except API paths
        set $cache_bypass 0;
        if ($request_uri ~* ^/api/) {
            set $cache_bypass 1;
        }
        proxy_no_cache $cache_bypass;
        proxy_cache_bypass $cache_bypass $http_pragma $http_authorization;
        {{end}}
        proxy_cache proxy_cache;
        proxy_cache_key $scheme$host$request_uri;
        proxy_cache_valid 200 301 302 {{if .Host.CacheTTL}}{{.Host.CacheTTL}}{{else}}1h{{end}};
        proxy_cache_use_stale error timeout http_500 http_502 http_503 http_504;
        add_header X-Cache-Status $upstream_cache_status always;
        {{end}}
    }
{{if .GeoRestriction}}{{if .GeoRestriction.ChallengeMode}}
    location @challenge_redirect {
        return 302 /api/v1/challenge/page?host={{.Host.ID}}&reason=geo_restriction&return=$scheme://$host$request_uri;
    }
{{end}}{{end}}
{{end}}

{{if .RateLimit}}{{if .RateLimit.Enabled}}
    # Rate limited response handler
    location @rate_limited {
        set $block_reason_var "rate_limit";
        return {{.RateLimit.LimitResponse}};
    }
{{end}}{{end}}

{{if .BlockedCloudIPRanges}}{{if .CloudProviderChallengeMode}}
    # Cloud provider challenge redirect handler
    location @cloud_challenge {
        return 302 /api/v1/challenge/page?host={{.Host.ID}}&reason=cloud_provider&return=$scheme://$host$request_uri;
    }
{{end}}{{end}}

{{if .Host.AdvancedConfig}}
    # Advanced configuration
    {{.Host.AdvancedConfig}}
{{end}}
}

{{if .Host.SSLEnabled}}
server {
    listen 443 ssl;
    listen [::]:443 ssl;
{{if .Host.SSLHTTP2}}
    # HTTP/2 over TCP (new directive style)
    http2 on;
{{end}}
{{if .Host.SSLHTTP3}}
    # HTTP/3 over QUIC (UDP)
    listen 443 quic;
    listen [::]:443 quic;
{{end}}
    server_name {{join .Host.DomainNames " "}};

    # Initialize tracking variables
    set $block_reason_var "-";
    set $bot_category_var "-";
    set $geo_blocked 0;

    # Skip security checks for ACME HTTP-01 Challenge (not typically used on HTTPS, but for consistency)
    set $skip_security_for_acme 0;
    if ($request_uri ~ "^/.well-known/acme-challenge/") {
        set $skip_security_for_acme 1;
    }
    # Also skip for challenge page to prevent redirect loops
    if ($request_uri ~ "^/api/v1/challenge/") {
        set $skip_security_for_acme 1;
    }

    # SSL configuration
    ssl_certificate /etc/nginx/certs/{{certPath .Host}}/fullchain.pem;
    ssl_certificate_key /etc/nginx/certs/{{certPath .Host}}/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
{{if .Host.SSLHTTP3}}
    # HTTP/3 settings
    ssl_early_data on;
{{end}}

    # Custom error pages for upstream errors
    error_page 502 /error_502.html;
    error_page 503 /error_503.html;
    error_page 504 /error_504.html;
    location = /error_502.html { internal; root /etc/nginx/html; try_files /502.html =502; }
    location = /error_503.html { internal; root /etc/nginx/html; try_files /503.html =503; }
    location = /error_504.html { internal; root /etc/nginx/html; try_files /504.html =504; }

    # Custom error page for security blocks (WAF, block_exploits, geo restriction, bot filter, etc.)
    error_page 403 @blocked;
    location @blocked {
        root /etc/nginx/html;
        default_type text/html;
        try_files /403.html =403;
    }

{{if .GeoRestriction}}{{if .GeoRestriction.Enabled}}{{if not .GeoRestriction.ChallengeMode}}
    # Geo Restriction ({{.GeoRestriction.Mode}}) - Direct Block Mode (processed BEFORE WAF for performance){{if .GeoRestriction.AllowPrivateIPs}} - Private IPs Allowed{{end}}{{if .GeoRestriction.AllowSearchBots}} - Search Bots Allowed{{end}}
{{if .GeoRestriction.AllowSearchBots}}{{if .SearchEnginesList}}
    # Check if request is from a search engine bot (uses dynamic list from system settings)
    set $is_search_bot 0;
    if ($http_user_agent ~* ({{toRegexPattern .SearchEnginesList}})) {
        set $is_search_bot 1;
    }
{{end}}{{end}}
{{if len .GeoRestriction.AllowedIPs}}
    # Priority Allow IPs/CIDRs - bypass geo restriction if matched
    set $geo_allowed_ip 0;
{{range .GeoRestriction.AllowedIPs}}
{{if isCIDR .}}
    if ($remote_addr ~ "{{cidrToNginxPattern .}}") {
        set $geo_allowed_ip 1;
    }
{{else}}
    if ($remote_addr = "{{.}}") {
        set $geo_allowed_ip 1;
    }
{{end}}
{{end}}
    # Apply geo restriction only if not in allowed IPs
    set $geo_block_check "";
{{if eq .GeoRestriction.Mode "whitelist"}}
    if ($geoip2_country_code !~ "^({{join .GeoRestriction.Countries "|"}}{{if .GeoRestriction.AllowPrivateIPs}}|--{{end}})$") {
        set $geo_block_check "Y";
        set $block_reason_var "geo_block";
    }
{{else}}
    if ($geoip2_country_code ~ "^({{join .GeoRestriction.Countries "|"}})$") {
        set $geo_block_check "Y";
        set $block_reason_var "geo_block";
    }
{{if .GeoRestriction.AllowPrivateIPs}}
    # Allow private IPs (geo code "--")
    if ($geoip2_country_code = "--") {
        set $geo_block_check "";
    }
{{end}}
{{end}}
{{if .GeoRestriction.AllowSearchBots}}
    # Allow search engine bots - bypass geo restriction
    if ($is_search_bot = 1) {
        set $geo_block_check "";
        set $block_reason_var "-";
    }
{{end}}
    # Combine checks: block only if geo_allowed_ip=0 AND geo_block_check=Y AND not ACME challenge
    set $geo_final_block "${geo_allowed_ip}${geo_block_check}${skip_security_for_acme}";
    if ($geo_final_block = "0Y0") {
        return 403;
    }
{{else}}
{{if .GeoRestriction.AllowSearchBots}}
    # Allow search engine bots - bypass geo restriction
    set $geo_block_check "";
{{if eq .GeoRestriction.Mode "whitelist"}}
    if ($geoip2_country_code !~ "^({{join .GeoRestriction.Countries "|"}}{{if .GeoRestriction.AllowPrivateIPs}}|--{{end}})$") {
        set $geo_block_check "Y";
        set $block_reason_var "geo_block";
    }
{{else}}
    if ($geoip2_country_code ~ "^({{join .GeoRestriction.Countries "|"}})$") {
        set $geo_block_check "Y";
        set $block_reason_var "geo_block";
    }
{{if .GeoRestriction.AllowPrivateIPs}}
    # Allow private IPs (geo code "--")
    if ($geoip2_country_code = "--") {
        set $geo_block_check "";
    }
{{end}}
{{end}}
    # Allow search bots
    if ($is_search_bot = 1) {
        set $geo_block_check "";
        set $block_reason_var "-";
    }
    # Skip geo block for ACME challenge
    set $geo_block_final "${geo_block_check}${skip_security_for_acme}";
    if ($geo_block_final = "Y0") {
        return 403;
    }
{{else}}
{{if eq .GeoRestriction.Mode "whitelist"}}
    # Check geo restriction (skip for ACME challenge)
    set $geo_direct_block "";
    if ($geoip2_country_code !~ "^({{join .GeoRestriction.Countries "|"}}{{if .GeoRestriction.AllowPrivateIPs}}|--{{end}})$") {
        set $geo_direct_block "Y";
        set $block_reason_var "geo_block";
    }
    set $geo_direct_final "${geo_direct_block}${skip_security_for_acme}";
    if ($geo_direct_final = "Y0") {
        return 403;
    }
{{else}}
    # Check geo restriction (skip for ACME challenge)
    set $geo_direct_block "";
    if ($geoip2_country_code ~ "^({{join .GeoRestriction.Countries "|"}})$") {
        set $geo_direct_block "Y";
        set $block_reason_var "geo_block";
    }
{{if .GeoRestriction.AllowPrivateIPs}}
    # Allow private IPs (geo code "--") - skip block
    if ($geoip2_country_code = "--") {
        set $geo_direct_block "";
        set $block_reason_var "-";
    }
{{end}}
    set $geo_direct_final "${geo_direct_block}${skip_security_for_acme}";
    if ($geo_direct_final = "Y0") {
        return 403;
    }
{{end}}
{{end}}
{{end}}
{{end}}{{end}}{{end}}

{{if .Host.WAFEnabled}}
    # WAF (ModSecurity) - {{.Host.WAFMode}} mode
    # Ensure Host header is set for HTTP/3 requests (uses :authority pseudo-header)
    more_set_input_headers "Host: $host";
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/{{wafConfig .Host}};
{{end}}

{{if .GeoRestriction}}{{if .GeoRestriction.Enabled}}{{if .GeoRestriction.ChallengeMode}}
    # Geo Restriction ({{.GeoRestriction.Mode}}) - Challenge Mode (processed AFTER WAF){{if .GeoRestriction.AllowPrivateIPs}} - Private IPs Allowed{{end}}{{if .GeoRestriction.AllowSearchBots}} - Search Bots Allowed{{end}}
{{if .GeoRestriction.AllowSearchBots}}{{if .SearchEnginesList}}
    # Check if request is from a search engine bot (uses dynamic list from system settings)
    set $is_search_bot 0;
    if ($http_user_agent ~* ({{toRegexPattern .SearchEnginesList}})) {
        set $is_search_bot 1;
    }
{{end}}{{end}}
    # Challenge mode: show CAPTCHA instead of blocking
    set $geo_blocked 0;
{{if eq .GeoRestriction.Mode "whitelist"}}
    if ($geoip2_country_code !~ "^({{join .GeoRestriction.Countries "|"}}{{if .GeoRestriction.AllowPrivateIPs}}|--{{end}})$") {
        set $geo_blocked 1;
        set $block_reason_var "geo_block";
    }
{{else}}
    if ($geoip2_country_code ~ "^({{join .GeoRestriction.Countries "|"}})$") {
        set $geo_blocked 1;
        set $block_reason_var "geo_block";
    }
{{if .GeoRestriction.AllowPrivateIPs}}
    # Allow private IPs (geo code "--")
    if ($geoip2_country_code = "--") {
        set $geo_blocked 0;
    }
{{end}}
{{end}}
{{if len .GeoRestriction.AllowedIPs}}
    # Priority Allow IPs/CIDRs - bypass geo restriction if matched
{{range .GeoRestriction.AllowedIPs}}
{{if isCIDR .}}
    if ($remote_addr ~ "{{cidrToNginxPattern .}}") {
        set $geo_blocked 0;
        set $block_reason_var "-";
    }
{{else}}
    if ($remote_addr = "{{.}}") {
        set $geo_blocked 0;
        set $block_reason_var "-";
    }
{{end}}
{{end}}
{{end}}
{{if .GeoRestriction.AllowSearchBots}}
    # Allow search engine bots - bypass geo challenge
    if ($is_search_bot = 1) {
        set $geo_blocked 0;
        set $block_reason_var "-";
    }
{{end}}
{{end}}{{end}}{{end}}

{{if .AccessList}}{{if .AccessList.Items}}
    # Access List: {{.AccessList.Name}}
    # Note: Access list denials will have block_reason set to access_denied
    set $block_reason_var "access_denied";
{{if .AccessList.SatisfyAny}}    satisfy any;{{end}}
{{range .AccessList.Items}}
    {{.Directive}} {{.Address}};{{if .Description}} # {{.Description}}{{end}}
{{end}}
    deny all;
{{end}}{{end}}

{{if .Host.BlockExploits}}
    # Block common exploits (database-managed rules)
{{if hasExploitRules .ExploitBlockRules}}
    # Query string rules (SQL injection, XSS, etc.) with URI exception handling
{{if hasRulesOfType .ExploitBlockRules "query_string"}}
    set $exploit_qs_block 0;
    set $exploit_qs_rule "-";
{{range filterRulesByPatternType .ExploitBlockRules "query_string"}}
    # {{.Name}} ({{.Category}})
    if ($query_string ~* "{{escapeNginxPattern .Pattern}}") {
        set $exploit_qs_block 1;
        set $exploit_qs_rule "{{.ID}}";
    }
{{end}}
{{if hasMergedExceptions .GlobalBlockExploitsExceptions .Host.BlockExploitsExceptions}}
    # URI exceptions - skip query string blocking for these paths
{{range splitExceptions (mergeExceptions .GlobalBlockExploitsExceptions .Host.BlockExploitsExceptions)}}
    if ($request_uri ~* "{{.}}") {
        set $exploit_qs_block 0;
    }
{{end}}
{{end}}
    if ($exploit_qs_block = 1) {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var $exploit_qs_rule;
        return 403;
    }
{{end}}

    # Request URI rules with RFI exception handling
{{if hasRulesOfType .ExploitBlockRules "request_uri"}}
    set $rfi_block 0;
{{range filterRulesByPatternType .ExploitBlockRules "request_uri"}}
    # {{.Name}} ({{.Category}})
    if ($request_uri ~* "{{escapeNginxPattern .Pattern}}") {
        set $rfi_block 1;
    }
{{end}}
{{if hasMergedExceptions .GlobalBlockExploitsExceptions .Host.BlockExploitsExceptions}}
    # Dynamic exceptions from database (global + host-specific)
{{range splitExceptions (mergeExceptions .GlobalBlockExploitsExceptions .Host.BlockExploitsExceptions)}}
    if ($request_uri ~* "{{.}}") {
        set $rfi_block 0;
    }
{{end}}
{{end}}
    if ($rfi_block = 1) {
        set $block_reason_var "exploit_block";
        return 403;
    }
{{end}}

    # User-agent rules (scanner/tool detection)
{{if hasRulesOfType .ExploitBlockRules "user_agent"}}
{{range filterRulesByPatternType .ExploitBlockRules "user_agent"}}
    # {{.Name}} ({{.Category}})
    if ($http_user_agent ~* "{{escapeNginxPattern .Pattern}}") {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "{{.ID}}";
        set $bot_category_var "scanner";
        return 403;
    }
{{end}}
{{end}}

    # HTTP method rules
{{if hasRulesOfType .ExploitBlockRules "request_method"}}
{{range filterRulesByPatternType .ExploitBlockRules "request_method"}}
    # {{.Name}} ({{.Category}})
    if ($request_method ~* "{{escapeNginxPattern .Pattern}}") {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "{{.ID}}";
        return 405;
    }
{{end}}
{{end}}
{{else}}
    # Fallback: No DB rules found, using hardcoded rules
    # SQL injection attempts in query string
    if ($query_string ~* "union.*select") {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "SQLI-FALLBACK-001";
        return 403;
    }
    if ($query_string ~* "(;|<|>|'|\"|\)|%0A|%0D|%22|%27|%3C|%3E|%00)") {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "SQLI-FALLBACK-002";
        return 403;
    }
    # File injection / path traversal (RFI)
    set $rfi_block 0;
    if ($query_string ~* "[a-zA-Z0-9_]=https?://") {
        set $rfi_block 1;
    }
{{if hasMergedExceptions .GlobalBlockExploitsExceptions .Host.BlockExploitsExceptions}}
{{range splitExceptions (mergeExceptions .GlobalBlockExploitsExceptions .Host.BlockExploitsExceptions)}}
    if ($request_uri ~* "{{.}}") {
        set $rfi_block 0;
    }
{{end}}
{{end}}
    if ($rfi_block = 1) {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "RFI-FALLBACK-001";
        return 403;
    }
    if ($query_string ~* "\.\./") {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "LFI-FALLBACK-001";
        return 403;
    }
    # Block exploit tools and scanners
    if ($http_user_agent ~* (nikto|sqlmap|dirbuster|nmap|nessus|openvas|w3af|acunetix|havij|appscan|webscarab|webinspect)) {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "SCAN-FALLBACK-001";
        set $bot_category_var "scanner";
        return 403;
    }
    # Block suspicious request methods
    if ($request_method !~ ^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$) {
        set $block_reason_var "exploit_block";
        set $exploit_rule_var "METHOD-FALLBACK-001";
        return 405;
    }
{{end}}
{{end}}

{{if .BannedIPs}}
    # Banned IPs check
    if ($banned_ip_{{sanitizeID .Host.ID}} = 1) {
        set $block_reason_var "banned_ip";
        return 403;
    }
{{end}}

{{if .BlockedCloudIPRanges}}
    # Blocked Cloud Provider IPs check
    # Skip for ACME challenge and challenge page (prevents redirect loops)
    # Priority Allow IPs bypass cloud provider blocking
    set $is_priority_allow_cloud $skip_security_for_acme;
{{if and .GeoRestriction (len .GeoRestriction.AllowedIPs)}}
{{range .GeoRestriction.AllowedIPs}}
{{if isCIDR .}}
    if ($remote_addr ~ "{{cidrToNginxPattern .}}") {
        set $is_priority_allow_cloud 1;
    }
{{else}}
    if ($remote_addr = "{{.}}") {
        set $is_priority_allow_cloud 1;
    }
{{end}}
{{end}}
{{end}}
{{if .CloudProviderAllowSearchBots}}{{if .SearchEnginesList}}
    # Allow search engine bots to bypass cloud provider blocking
    if ($http_user_agent ~* ({{toRegexPattern .SearchEnginesList}})) {
        set $is_priority_allow_cloud 1;
    }
{{end}}{{end}}
    set $cloud_block_check_{{sanitizeID .Host.ID}} "${blocked_cloud_{{sanitizeID .Host.ID}}}${is_priority_allow_cloud}";
{{if .CloudProviderChallengeMode}}
    # Challenge mode - redirect to challenge page instead of blocking (skip for priority IPs, search bots, and ACME/challenge paths)
    if ($cloud_block_check_{{sanitizeID .Host.ID}} = "10") {
        set $block_reason_var "cloud_provider_challenge";
        return 418; # Use 418 as internal marker for cloud challenge redirect
    }
    error_page 418 = @cloud_challenge;
{{else}}
    # Block mode (skip for priority IPs, search bots, and ACME/challenge paths)
    if ($cloud_block_check_{{sanitizeID .Host.ID}} = "10") {
        set $block_reason_var "cloud_provider_block";
        return 403;
    }
{{end}}
{{end}}

{{if .BotFilter}}{{if .BotFilter.Enabled}}
    # Bot Filter - uses error_page 403 for custom error page
    # Priority Allow IPs bypass all bot filtering
    # Also bypass for ACME challenge
    set $priority_allow $skip_security_for_acme;
{{if and .GeoRestriction (len .GeoRestriction.AllowedIPs)}}
{{range .GeoRestriction.AllowedIPs}}
{{if isCIDR .}}
    if ($remote_addr ~ "{{cidrToNginxPattern .}}") {
        set $priority_allow 1;
    }
{{else}}
    if ($remote_addr = "{{.}}") {
        set $priority_allow 1;
    }
{{end}}
{{end}}
{{end}}
{{if .BotFilter.AllowSearchEngines}}{{if .SearchEnginesList}}
    # Allow search engine bots to bypass bot filter
    if ($http_user_agent ~* ({{toRegexPattern .SearchEnginesList}})) {
        set $priority_allow 1;
    }
{{end}}{{end}}
{{if .BotFilter.BlockBadBots}}{{if .BadBotsList}}
    set $block_bad_bot 0;
    if ($http_user_agent ~* ({{toRegexPattern .BadBotsList}})) {
        set $block_bad_bot 1;
        set $block_reason_var "bot_filter";
        set $bot_category_var "bad_bot";
    }
    # Block only if not in priority allow list
    set $bad_bot_check "${priority_allow}${block_bad_bot}";
    if ($bad_bot_check = "01") {
        return 403;
    }
{{end}}{{end}}
{{if .BotFilter.BlockAIBots}}{{if .AIBotsList}}
    set $block_ai_bot 0;
    if ($http_user_agent ~* ({{toRegexPattern .AIBotsList}})) {
        set $block_ai_bot 1;
        set $block_reason_var "bot_filter";
        set $bot_category_var "ai_bot";
    }
    # Block only if not in priority allow list
    set $ai_bot_check "${priority_allow}${block_ai_bot}";
    if ($ai_bot_check = "01") {
        return 403;
    }
{{end}}{{end}}
{{if .BotFilter.BlockSuspiciousClients}}{{if .SuspiciousClientsList}}
    set $block_suspicious 0;
    if ($http_user_agent ~* ({{toRegexPattern .SuspiciousClientsList}})) {
        set $block_suspicious 1;
        set $block_reason_var "bot_filter";
        set $bot_category_var "suspicious";
    }
    # Block only if not in priority allow list
    set $suspicious_check "${priority_allow}${block_suspicious}";
    if ($suspicious_check = "01") {
        return 403;
    }
{{end}}{{end}}
{{if .BotFilter.CustomBlockedAgents}}
    set $block_custom 0;
    if ($http_user_agent ~* ({{toRegexPattern .BotFilter.CustomBlockedAgents}})) {
        set $block_custom 1;
        set $block_reason_var "bot_filter";
        set $bot_category_var "custom";
    }
    # Block only if not in priority allow list
    set $custom_check "${priority_allow}${block_custom}";
    if ($custom_check = "01") {
        return 403;
    }
{{end}}
{{end}}{{end}}

{{if .RateLimit}}{{if .RateLimit.Enabled}}
    # Rate Limiting
    limit_req zone=rate_{{sanitizeID .Host.ID}} burst={{.RateLimit.BurstSize}} nodelay;
    limit_req_status {{.RateLimit.LimitResponse}};
    error_page {{.RateLimit.LimitResponse}} = @rate_limited;
{{end}}{{end}}

{{if .URIBlock}}{{if .URIBlock.Enabled}}
    # URI Path Blocking
{{range .URIBlock.Rules}}{{if .Enabled}}
    # Block: {{.Description}}
    {{uriLocationDirective .MatchType .Pattern}} {
{{if hasURIBlockExceptionIPs $.URIBlock}}
        # Check exception IPs
        set $uri_block_exception 0;
{{if $.URIBlock.AllowPrivateIPs}}
        # Allow private IPs (10.x, 172.16-31.x, 192.168.x)
        if ($remote_addr ~ "^(10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)") {
            set $uri_block_exception 1;
        }
{{end}}
{{range $.URIBlock.ExceptionIPs}}
{{if isCIDR .}}
        if ($remote_addr ~ "{{cidrToNginxPattern .}}") {
            set $uri_block_exception 1;
        }
{{else}}
        if ($remote_addr = "{{.}}") {
            set $uri_block_exception 1;
        }
{{end}}
{{end}}
        if ($uri_block_exception = 0) {
            set $block_reason_var "uri_block";
            return 403;
        }
        # Pass through to upstream if exception matched
        {{if $.Upstream}}proxy_pass http://{{$.Upstream.Name}};{{else}}proxy_pass {{$.Host.ForwardScheme}}://{{$.Host.ForwardHost}}:{{$.Host.ForwardPort}};{{end}}
        include /etc/nginx/includes/proxy_params.conf;
{{else}}
        set $block_reason_var "uri_block";
        return 403;
{{end}}
    }
{{end}}{{end}}
{{end}}{{end}}

{{if .GeoRestriction}}{{if .GeoRestriction.ChallengeMode}}
    # Challenge validation endpoint (internal)
    location = /_challenge/validate {
        internal;
        proxy_pass http://{{apiHost}}/api/v1/challenge/validate;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Proxy-Host-ID "{{.Host.ID}}";
        proxy_set_header X-Challenge-Token $cookie_ng_challenge;
        proxy_set_header X-Geo-Blocked $geo_blocked;
        # Fast timeout - fail fast if API is down
        proxy_connect_timeout 2s;
        proxy_read_timeout 5s;
    }

    # API error fallback - allow traffic through when API is down
    location @api_fallback {
        # API is down - allow request to proceed (graceful degradation)
        access_log /etc/nginx/logs/access_raw.log main;
        {{if .Upstream}}proxy_pass http://{{.Upstream.Name}};{{else}}proxy_pass {{.Host.ForwardScheme}}://{{.Host.ForwardHost}}:{{.Host.ForwardPort}};{{end}}
        include /etc/nginx/includes/proxy_params.conf;
    }

    # Challenge API - Bypass GeoIP and proxy to API service
    location /api/v1/challenge/ {
        # Disable WAF for challenge parameters (return URL triggers SQLi/RFI rules)
        modsecurity off;

        proxy_pass http://{{apiHost}}/api/v1/challenge/;
        proxy_pass_request_body on;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        # Use $remote_addr directly to prevent X-Forwarded-For header spoofing
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
{{end}}{{end}}

    location / {
{{if .GeoRestriction}}{{if .GeoRestriction.ChallengeMode}}
        # Check challenge token for geo-blocked users (skip for search bots)
        set $challenge_check 0;
        if ($geo_blocked = 1) {
            set $challenge_check 1;
        }
{{if .GeoRestriction.AllowSearchBots}}
        # Search bots bypass challenge completely
        if ($is_search_bot = 1) {
            set $challenge_check 0;
        }
{{end}}
        set $challenge_check_final $challenge_check;
        if ($cookie_ng_challenge = "") {
            set $challenge_check_final "${challenge_check}1";
        }
        if ($challenge_check_final = 11) {
            # No token, redirect to challenge page
            return 302 /api/v1/challenge/page?host={{.Host.ID}}&reason=geo_restriction&return=$scheme://$host$request_uri;
        }
        # Validate existing token for geo-blocked users
        # Note: API returns 200 for search bots, so they won't be redirected
        auth_request /_challenge/validate;
        error_page 401 = @challenge_redirect;
        error_page 500 502 503 504 = @api_fallback;
{{end}}{{end}}
        {{if .Upstream}}proxy_pass http://{{.Upstream.Name}};{{else}}proxy_pass {{.Host.ForwardScheme}}://{{.Host.ForwardHost}}:{{.Host.ForwardPort}};{{end}}
        include /etc/nginx/includes/proxy_params.conf;
        {{if .GlobalSettings}}
        # Global proxy settings
        {{if gt .GlobalSettings.ProxyConnectTimeout 0}}proxy_connect_timeout {{.GlobalSettings.ProxyConnectTimeout}}s;{{end}}
        {{if gt .GlobalSettings.ProxySendTimeout 0}}proxy_send_timeout {{.GlobalSettings.ProxySendTimeout}}s;{{end}}
        {{if gt .GlobalSettings.ProxyReadTimeout 0}}proxy_read_timeout {{.GlobalSettings.ProxyReadTimeout}}s;{{end}}
        {{if gt .GlobalSettings.ClientBodyTimeout 0}}client_body_timeout {{.GlobalSettings.ClientBodyTimeout}}s;{{end}}
        {{if gt .GlobalSettings.SendTimeout 0}}send_timeout {{.GlobalSettings.SendTimeout}}s;{{end}}
        {{if .GlobalSettings.ClientMaxBodySize}}client_max_body_size {{.GlobalSettings.ClientMaxBodySize}};{{end}}
        # Proxy buffer settings (from Global Settings)
        {{if .GlobalSettings.ProxyBufferSize}}proxy_buffer_size {{.GlobalSettings.ProxyBufferSize}};{{end}}
        {{if .GlobalSettings.ProxyBuffers}}proxy_buffers {{.GlobalSettings.ProxyBuffers}};{{end}}
        {{if .GlobalSettings.ProxyBusyBuffersSize}}proxy_busy_buffers_size {{.GlobalSettings.ProxyBusyBuffersSize}};{{end}}
        {{end}}
        {{if .Host.AllowWebsocketUpgrade}}
        # WebSocket support (proxy_http_version already set in proxy_params.conf)
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $connection_upgrade;
        {{end}}
        {{if .Host.SSLHTTP3}}
        # HTTP/3 Alt-Svc header
        add_header Alt-Svc 'h3=":443"; ma=86400' always;
        {{end}}
        {{if .Host.CacheEnabled}}
        # Caching
        {{if .Host.CacheStaticOnly}}
        # Static assets only - bypass cache for API and dynamic content
        set $cache_bypass 1;
        if ($request_uri ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot|webp|avif|mp4|webm|pdf)$) {
            set $cache_bypass 0;
        }
        proxy_no_cache $cache_bypass;
        proxy_cache_bypass $cache_bypass $http_pragma $http_authorization;
        {{else}}
        # All content except API paths
        set $cache_bypass 0;
        if ($request_uri ~* ^/api/) {
            set $cache_bypass 1;
        }
        proxy_no_cache $cache_bypass;
        proxy_cache_bypass $cache_bypass $http_pragma $http_authorization;
        {{end}}
        proxy_cache proxy_cache;
        proxy_cache_key $scheme$host$request_uri;
        proxy_cache_valid 200 301 302 {{if .Host.CacheTTL}}{{.Host.CacheTTL}}{{else}}1h{{end}};
        proxy_cache_use_stale error timeout http_500 http_502 http_503 http_504;
        add_header X-Cache-Status $upstream_cache_status always;
        {{end}}
        {{if .SecurityHeaders}}{{if .SecurityHeaders.Enabled}}
        # Security Headers (in location block to ensure they are applied)
        {{if .SecurityHeaders.HSTSEnabled}}
        add_header Strict-Transport-Security "max-age={{.SecurityHeaders.HSTSMaxAge}}{{if .SecurityHeaders.HSTSIncludeSubdomains}}; includeSubDomains{{end}}{{if .SecurityHeaders.HSTSPreload}}; preload{{end}}" always;
        {{end}}
        {{if .SecurityHeaders.XFrameOptions}}
        add_header X-Frame-Options "{{.SecurityHeaders.XFrameOptions}}" always;
        {{end}}
        {{if .SecurityHeaders.XContentTypeOptions}}
        add_header X-Content-Type-Options "nosniff" always;
        {{end}}
        {{if .SecurityHeaders.XXSSProtection}}
        add_header X-XSS-Protection "1; mode=block" always;
        {{end}}
        {{if .SecurityHeaders.ReferrerPolicy}}
        add_header Referrer-Policy "{{.SecurityHeaders.ReferrerPolicy}}" always;
        {{end}}
        {{if .SecurityHeaders.ContentSecurityPolicy}}
        add_header Content-Security-Policy "{{.SecurityHeaders.ContentSecurityPolicy}}" always;
        {{end}}
        {{if .SecurityHeaders.PermissionsPolicy}}
        add_header Permissions-Policy "{{.SecurityHeaders.PermissionsPolicy}}" always;
        {{end}}
        {{end}}{{end}}
    }

{{if .GeoRestriction}}{{if .GeoRestriction.ChallengeMode}}
    location @challenge_redirect {
        return 302 /api/v1/challenge/page?host={{.Host.ID}}&reason=geo_restriction&return=$scheme://$host$request_uri;
    }
{{end}}{{end}}

{{if .RateLimit}}{{if .RateLimit.Enabled}}
    # Rate limited response handler
    location @rate_limited {
        set $block_reason_var "rate_limit";
        return {{.RateLimit.LimitResponse}};
    }
{{end}}{{end}}

{{if .BlockedCloudIPRanges}}{{if .CloudProviderChallengeMode}}
    # Cloud provider challenge redirect handler
    location @cloud_challenge {
        return 302 /api/v1/challenge/page?host={{.Host.ID}}&reason=cloud_provider&return=$scheme://$host$request_uri;
    }
{{end}}{{end}}

{{if .Host.AdvancedConfig}}
    # Advanced configuration
    {{.Host.AdvancedConfig}}
{{end}}
}
{{end}}
{{end}}
`

// ProxyHostConfigData holds all data for proxy host config generation
type ProxyHostConfigData struct {
	Host                          *model.ProxyHost
	AccessList                    *model.AccessList
	GeoRestriction                *model.GeoRestriction
	RateLimit                     *model.RateLimit
	SecurityHeaders               *model.SecurityHeaders
	BotFilter                     *model.BotFilter
	BannedIPs                     []model.BannedIP
	Upstream                      *model.Upstream
	GlobalSettings                *model.GlobalSettings // Global nginx settings (timeouts, compression, etc.)
	SuspiciousClientsList         string                // Newline-separated list of suspicious clients from system settings
	BadBotsList                   string                // Newline-separated list of bad bots from system settings
	AIBotsList                    string                // Newline-separated list of AI bots from system settings
	SearchEnginesList             string                // Newline-separated list of allowed search engines from system settings
	BlockedCloudIPRanges          []string              // CIDR ranges of blocked cloud providers
	CloudProviderChallengeMode    bool                  // If true, show challenge instead of blocking cloud providers
	CloudProviderAllowSearchBots  bool                  // If true, allow search engine bots to bypass cloud provider blocking
	URIBlock                      *model.URIBlock       // URI path blocking settings
	GlobalBlockExploitsExceptions string                // Global newline-separated list of exploit exceptions from system settings
	ExploitBlockRules             []model.ExploitBlockRule // Dynamic exploit blocking rules from database
}
