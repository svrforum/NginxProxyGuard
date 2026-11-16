# Third-Party Licenses

Nginx Proxy Guard uses the following third-party software:

## Core Components

### TimescaleDB
- **License**: Timescale License (TSL)
- **Website**: https://github.com/timescale/timescaledb
- **License URL**: https://github.com/timescale/timescaledb/blob/main/tsl/LICENSE-TIMESCALE
- **Note**: TimescaleDB Community Edition is used for time-series data storage and compression. The Timescale License allows use with open source projects. See license for details.

### Nginx
- **License**: BSD-2-Clause
- **Website**: https://nginx.org/
- **Copyright**: (C) 2002-2024 Igor Sysoev, (C) 2011-2024 Nginx, Inc.

### ModSecurity
- **License**: Apache License 2.0
- **Website**: https://github.com/owasp-modsecurity/ModSecurity
- **Copyright**: (C) 2002-2024 Trustwave Holdings, Inc.

### OWASP Core Rule Set (CRS)
- **License**: Apache License 2.0
- **Website**: https://coreruleset.org/
- **Copyright**: (C) 2006-2024 Trustwave Holdings, Inc., OWASP Core Rule Set contributors

### MaxMind GeoIP2 / GeoLite2
- **License**: GeoLite2 End User License Agreement
- **Website**: https://www.maxmind.com/
- **Attribution**: This product includes GeoLite2 data created by MaxMind, available from https://www.maxmind.com

### Valkey
- **License**: BSD-3-Clause
- **Website**: https://valkey.io/
- **Note**: Optional cache (`valkey/valkey:9-alpine` in the default compose); NPG runs without it.

### cloudflared (Cloudflare Tunnel connector)
- **License**: Apache License 2.0
- **Website**: https://github.com/cloudflare/cloudflared
- **Note**: Bundled as a standalone binary in the nginx image (`CLOUDFLARED_VERSION` in `nginx/Dockerfile`); only runs when Cloudflare Tunnel is enabled.

### geoipupdate
- **License**: Apache License 2.0
- **Website**: https://github.com/maxmind/geoipupdate
- **Note**: Bundled in the nginx image to refresh the GeoLite2 databases.

### Swagger UI (swagger-ui-dist)
- **License**: Apache License 2.0
- **Website**: https://github.com/swagger-api/swagger-ui
- **Copyright**: (C) SmartBear Software
- **Note**: `swagger-ui.css`, `swagger-ui-bundle.js` and `swagger-ui-standalone-preset.js` from
  swagger-ui-dist 5.10.3 are vendored into the api image (`api/internal/handler/swaggerui/`) and
  served by the API, so `/api/docs` renders on installs with no internet egress. The pinned
  version lives in `SwaggerUIDistVersion` (`api/internal/handler/swagger.go`).

## Backend (Go) Dependencies

| Package | License | Website |
|---------|---------|---------|
| github.com/labstack/echo/v4 | MIT | https://echo.labstack.com/ |
| github.com/go-acme/lego/v4 | MIT | https://go-acme.github.io/lego/ |
| github.com/lib/pq | MIT | https://github.com/lib/pq |
| github.com/google/uuid | BSD-3-Clause | https://github.com/google/uuid |
| github.com/redis/go-redis/v9 | BSD-2-Clause | https://github.com/redis/go-redis |
| github.com/oschwald/geoip2-golang | ISC | https://github.com/oschwald/geoip2-golang |
| golang.org/x/crypto | BSD-3-Clause | https://golang.org/x/crypto |
| golang.org/x/oauth2 | BSD-3-Clause | https://golang.org/x/oauth2 |
| golang.org/x/sync | BSD-3-Clause | https://golang.org/x/sync |
| golang.org/x/time | BSD-3-Clause | https://golang.org/x/time |
| github.com/coreos/go-oidc/v3 | Apache-2.0 | https://github.com/coreos/go-oidc |
| github.com/prometheus/client_golang | Apache-2.0 | https://github.com/prometheus/client_golang |
| github.com/maypok86/otter/v2 | Apache-2.0 | https://github.com/maypok86/otter |
| github.com/oschwald/maxminddb-golang | ISC | https://github.com/oschwald/maxminddb-golang |
| github.com/robfig/cron/v3 | MIT | https://github.com/robfig/cron |
| github.com/shirou/gopsutil/v3 | BSD-3-Clause | https://github.com/shirou/gopsutil |
| github.com/joho/godotenv | MIT | https://github.com/joho/godotenv |

## Frontend (React) Dependencies

| Package | License | Website |
|---------|---------|---------|
| React | MIT | https://react.dev/ |
| @tanstack/react-query | MIT | https://tanstack.com/query |
| react-router-dom | MIT | https://reactrouter.com/ |
| recharts | MIT | https://recharts.org/ |
| i18next | MIT | https://www.i18next.com/ |
| Tailwind CSS | MIT | https://tailwindcss.com/ |
| Vite | MIT | https://vitejs.dev/ |
| react-i18next | MIT | https://react.i18next.com/ |
| i18next-browser-languagedetector | MIT | https://github.com/i18next/i18next-browser-languageDetector |
| react-simple-maps | MIT | https://github.com/zcreativelabs/react-simple-maps |
| topojson-client | ISC | https://github.com/topojson/topojson-client |
| react-datepicker | MIT | https://reactdatepicker.com/ |
| qrcode.react | ISC | https://github.com/zpao/qrcode.react |
| date-fns | MIT | https://date-fns.org/ |

## Nginx Modules

| Module | License | Website |
|--------|---------|---------|
| ModSecurity-nginx | Apache 2.0 | https://github.com/owasp-modsecurity/ModSecurity-nginx |
| ngx_brotli | BSD-2-Clause | https://github.com/google/ngx_brotli |
| headers-more-nginx-module | BSD-2-Clause | https://github.com/openresty/headers-more-nginx-module |
| ngx_http_geoip2_module | BSD-2-Clause | https://github.com/leev/ngx_http_geoip2_module |

---

## Apache License 2.0 Notice

The following components are licensed under the Apache License 2.0:

- ModSecurity (Copyright 2002-2024 Trustwave Holdings, Inc.)
- OWASP Core Rule Set (Copyright 2006-2024 Trustwave Holdings, Inc.)
- ModSecurity-nginx (Copyright 2015-2024 Trustwave Holdings, Inc.)
- cloudflared (Cloudflare, Inc.)
- geoipupdate (MaxMind, Inc.)
- Swagger UI / swagger-ui-dist (SmartBear Software)
- github.com/coreos/go-oidc (CoreOS and go-oidc contributors)
- github.com/prometheus/client_golang (The Prometheus Authors)
- github.com/maypok86/otter (Alexey Mayshev and contributors)

Licensed under the Apache License, Version 2.0 (the "License");
you may not use these files except in compliance with the License.
You may obtain a copy of the License at:

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

---

## GeoLite2 End User License Agreement

This product includes GeoLite2 data created by MaxMind, available from
https://www.maxmind.com. GeoLite2 databases are offered under the
GeoLite2 End User License Agreement. For the full license text, see:
https://www.maxmind.com/en/geolite2/eula
