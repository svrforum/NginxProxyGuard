# Third-Party Licenses

Nginx Proxy Guard uses the following third-party software:

## Core Components

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

## Backend (Go) Dependencies

| Package | License | Website |
|---------|---------|---------|
| github.com/labstack/echo/v4 | MIT | https://echo.labstack.com/ |
| github.com/go-acme/lego/v4 | MIT | https://go-acme.github.io/lego/ |
| github.com/lib/pq | MIT | https://github.com/lib/pq |
| github.com/google/uuid | BSD-3-Clause | https://github.com/google/uuid |
| github.com/redis/go-redis/v9 | BSD-2-Clause | https://github.com/redis/go-redis |
| github.com/oschwald/geoip2-golang | ISC | https://github.com/oschwald/geoip2-golang |
| github.com/cloudflare/cloudflare-go | BSD-3-Clause | https://github.com/cloudflare/cloudflare-go |
| golang.org/x/crypto | BSD-3-Clause | https://golang.org/x/crypto |

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
