# Security Policy

## Reporting a Vulnerability

Please **do not open a public issue** for security vulnerabilities.

Use GitHub's private vulnerability reporting instead:

1. Go to the repository's **Security** tab
2. Click **Report a vulnerability**
3. Describe the issue, affected versions, and reproduction steps

You can expect an initial response within **7 days**. Once a fix is released,
the report will be disclosed via a GitHub Security Advisory with credit to the
reporter (unless you prefer to remain anonymous).

Direct link: https://github.com/svrforum/NginxProxyGuard/security/advisories/new

## Supported Versions

Only the **latest release** receives security fixes. NginxProxyGuard follows a
rolling release model — please upgrade to the most recent version before
reporting issues against older releases.

| Version | Supported |
|---------|-----------|
| Latest release | ✅ |
| Older releases | ❌ (upgrade first) |

## Scope

In scope:

- The API server (`api/`), admin UI (`ui/`), and nginx/ModSecurity layer (`nginx/`)
- The official Docker images (`svrforum/nginxproxyguard-{api,ui,nginx}`)
- Default `docker-compose.yml` deployment configuration

Out of scope:

- Vulnerabilities in upstream dependencies that are already public (report
  upstream; we track them via Dependabot)
- Issues requiring a fully compromised host or Docker daemon
- Self-modified forks or non-default deployment configurations

## Hardening Guidance for Operators

- **Do not expose the admin UI (port 81) to the internet.** Keep it on your
  LAN/VPN, or front it with its own proxy host protected by access lists and
  2FA.
- Complete the initial setup immediately — since v2.24.6 the server blocks all
  protected APIs until the default credentials are changed.
- Enable 2FA (TOTP) for the admin account.
- Use API tokens with the minimum permission scopes needed.
