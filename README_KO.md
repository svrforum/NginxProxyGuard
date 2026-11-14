<div align="center">

# Nginx Proxy Guard

### Make Your Nginx Smarter & Safer

[English](./README.md) | **한국어**

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./NPG_banner_dark.png">
  <img src="./NPG_banner.png" alt="Nginx Proxy Guard" width="520">
</picture>

[![Version](https://img.shields.io/github/v/release/svrforum/NginxProxyGuard?style=for-the-badge&color=brightgreen&label=Version)](https://github.com/svrforum/NginxProxyGuard/releases)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/svrforum/NginxProxyGuard?style=for-the-badge&logo=github&color=gold)](https://github.com/svrforum/NginxProxyGuard/stargazers)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/u/svrforum)

[![Nginx](https://img.shields.io/badge/Nginx-1.30.4-009639?style=for-the-badge&logo=nginx&logoColor=white)](https://nginx.org/)
[![ModSecurity](https://img.shields.io/badge/ModSecurity-v3.0.15-red?style=for-the-badge)](https://modsecurity.org/)
[![OWASP CRS](https://img.shields.io/badge/OWASP_CRS-v4.26.0-orange?style=for-the-badge)](https://coreruleset.org/)
[![HTTP/3](https://img.shields.io/badge/HTTP/3-QUIC-blue?style=for-the-badge)]()

<p align="center">
  <strong>직관적인 웹 UI를 통해 프록시 호스트, SSL 인증서,<br/>보안 규칙을 관리할 수 있는 안전하고 빠른 솔루션</strong>
</p>

<p align="center">
  <a href="https://nginxproxyguard.com">🌐 웹사이트</a> •
  <a href="https://nginxproxyguard.com/ko/docs">📖 문서</a> •
  <a href="#-주요-기능">✨ 기능</a> •
  <a href="#-빠른-시작">🚀 빠른 시작</a> •
  <a href="#-기술-스택">🛠 기술 스택</a> •
  <a href="#-api-문서">📚 API</a>
</p>

<p align="center">
  <em>이 프로젝트가 마음에 드신다면, 후원이 큰 힘이 됩니다 ↓</em><br/>
  <a href="https://github.com/sponsors/svrforum" target="_blank"><img src="https://img.shields.io/badge/%ED%9B%84%EC%9B%90-GitHub%20Sponsors-EA4AAA?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="GitHub Sponsors로 Nginx Proxy Guard 후원하기"></a>
  <a href="https://buymeacoffee.com/svrforum" target="_blank"><img src="https://img.shields.io/badge/%E2%98%95%20Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black" alt="Buy Me a Coffee"></a>
</p>

---

</div>

## ✨ 주요 기능

**강력한 보안, 쉬운 관리** - Nginx의 복잡함은 줄이고, 보안은 극대화

### 🔒 SSL 자동화
Let's Encrypt 통합 및 자동 갱신. DNS-01 챌린지를 통한 와일드카드 인증서 지원. **Cloudflare**, **AWS Route 53**, **DuckDNS**, **Dynu**, **IONOS** 등 다양한 DNS 프로바이더 지원.

Route 53은 액세스 키 쌍 없이도 사용할 수 있습니다. DNS 프로바이더에서 **AWS 기본 자격 증명 사용**을 켜면 AWS 기본 자격 증명 체인(EC2 인스턴스 역할, ECS 태스크 역할, 또는 `api` 컨테이너의 `AWS_*` 환경 변수)으로 인증합니다. API 컨테이너는 bridge 네트워크에서 실행되므로 EC2에서는 인스턴스 메타데이터 서비스가 두 번째 홉을 허용해야 합니다: IMDSv2에 `HttpPutResponseHopLimit` 2 (`aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required --http-put-response-hop-limit 2`).

### 🤖 봇 보호
80개 이상의 악성 봇과 50개 이상의 AI 크롤러를 자동 차단. 검색 엔진 허용 목록으로 정상 트래픽 보장. 의심스러운 요청에 대한 CAPTCHA 챌린지 모드.

### 📊 직관적인 대시보드
실시간 트래픽 모니터링, 보안 차단 로그, 인증서 상태, 서버 상태를 한눈에 확인.

### 🌍 GeoIP 접근 제어
국가별 트래픽 차단/허용 및 인터랙티브 세계 지도 시각화. MaxMind GeoIP2 통합 및 자동 업데이트.

### 📝 로그 뷰어 & 분석
강력한 필터링과 제외 패턴으로 Nginx 접근/에러 로그 분석. **TimescaleDB** 시계열 최적화 및 자동 압축.

### 🛡️ 웹 애플리케이션 방화벽
ModSecurity v3 + OWASP Core Rule Set v4.26. Paranoia Level 1-4, 전역 WAF 기본값 + 호스트별 재정의, 전역/호스트별 룰 제외(호스트 전체·URI 경로·단일 인자 범위 지정 가능), 익스플로잇 차단 규칙.

### ⚡ 요청 속도 제한
IP, URI, 또는 IP+URI 조합별 설정 가능한 속도 제한으로 DDoS 및 무차별 대입 공격 방어.

### 🔀 로드 밸런싱 & 업스트림
라운드 로빈, 최소 연결, IP 해시, 랜덤 분산과 서버별 가중치·백업 서버(`down`, `max_fails`, `fail_timeout`은 API로 설정)로 다중 백엔드 서버 지원. 장애 백엔드는 nginx의 `max_fails`/`fail_timeout`으로 수동적으로 제외되며, 능동 HTTP 헬스 체크는 아직 구현되지 않았습니다.

### 🔌 TCP/UDP Stream 프록시
같은 UI에서 Nginx `stream` 리버스 프록시를 관리합니다. TCP/UDP 리스너, 선택적 SNI preread 라우팅(TCP 전용), PROXY 프로토콜 수신/전송, stream 타임아웃, 설정 테스트, 백업/복원을 지원합니다. 차단된 IP는 stream 리스너에도 자동 적용됩니다.

**Stream 보안 범위** — `stream`은 L4(TCP/UDP)에서 동작하므로 HTTP 계층 보호는 **적용되지 않습니다**: ModSecurity(WAF), exploit 차단, bot filter, URI 차단, rate limit, access list는 모두 HTTP 전용입니다. IP 기반 차단(banned IPs)은 L4에서도 동작해 자동 주입됩니다. fail2ban과 GeoIP의 stream 적용은 follow-up으로 분리되어 있습니다.

> Stream 트래픽은 nginx 컨테이너 안의 `/var/log/nginx/stream_access.log`(+`stream_error.log`)에 기록됩니다. LogCollector가 stream 트래픽을 NPG 대시보드로 수집하는 기능은 follow-up으로 추적 중이며, 지금은 `docker logs npg-proxy` 또는 파일을 직접 확인하세요.

> `worker_connections`는 HTTP와 stream 리스너가 공유합니다. 장기 stream 세션이 많으면 HTTP 처리 용량에 영향을 줄 수 있으니, 무거운 stream 워크로드가 있으면 `worker_connections`를 늘리세요 (설정 → 글로벌 → "권장 설정 적용"으로 8192까지 자동 적용).

> `CustomStreamConfig`(고급 탭)는 임의의 nginx `stream` directive를 받으며 임의의 인터페이스/포트에 바인딩 가능합니다. 관리자 전용 기능으로 다루세요.

### 🔐 보안 헤더
HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Content-Security-Policy.

### 📋 접근 목록
화이트리스트 또는 블랙리스트를 위한 IP 기반 접근 제어 목록. CIDR 표기법 지원.
허용 규칙에 도메인 이름(DDNS 이름 등)도 지원 — 지금 조회되는 주소만 허용.
URI 차단 예외, 우선 허용, 속도 제한 예외, 전역 신뢰 IP도 도메인 이름을 지원 — 도메인은 IP 차단(밴)과 WAF를 넘지 못함.

### 💾 백업 & 복원
인증서, 설정, 데이터베이스를 포함한 전체 구성 백업. 예약된 자동 백업 지원.

### 🔑 API 토큰 관리
세분화된 권한, IP 제한, 만료 기간이 있는 API 토큰 생성. CI/CD 통합에 적합.

### 🔄 리다이렉트 호스트
HTTP에서 HTTPS 리다이렉트, 도메인 리다이렉트, 커스텀 리다이렉트 규칙.

### 📜 감사 로그
사용자 귀속 및 타임스탬프와 함께 모든 구성 변경 사항 추적.

### 🔐 2단계 인증
TOTP(Google Authenticator, Authy 등)를 사용한 관리자 계정용 선택적 2FA.

### 🌐 HTTP/3 & QUIC
UDP를 통한 더 빠르고 안정적인 연결을 위한 최신 프로토콜 지원.

### 🔐 보안 강화 (v2.2.0)
강화된 비밀번호 정책 (10자 이상, 복잡도 요구). IP/CIDR 입력 유효성 검증. 정규식 ReDoS 방지. Nginx 설정 실패 시 자동 롤백.

### 📡 필터 구독 (v2.7.0)
외부 IP/CIDR 차단 목록을 구독하여 Nginx에 자동 동기화. 프리셋 차단 목록 제공, 자동 갱신 스케줄링, 구독 간 및 차단 IP와의 중복 항목 자동 제거. 목록당 최대 25K, 전체 최대 100K 항목 지원.

### 🔮 포스트양자 TLS (v2.6.0)
미래 보안을 위한 ML-KEM (X25519MLKEM768) 하이브리드 키 교환 지원. 글로벌 SSL 설정에서 구성 가능, OpenSSL 3.5 호환.

### ⚙️ 프록시 버퍼링 제어 (v2.3.2)
글로벌 프록시 요청/응답 버퍼링 설정으로 세밀한 성능 튜닝. WebSocket, 스트리밍, 대용량 파일 업로드 시나리오에 유용.

### 🔍 설정 오류 진단 (v2.4.0)
프록시 호스트 설정 실패에 대한 실행 가능한 에러 가이드. 클릭 가능한 에러 배지와 상세 트러블슈팅. Nginx 시작 시 깨진 설정 자동 비활성화.

### 🌐 다이나믹 DNS (v2.21.0, 통합 v2.23.0)
공인 IP가 바뀌어도 도메인이 홈서버를 가리키도록 유지하는 내장 DDNS (Cloudflare / DuckDNS / Dynu / Infomaniak). 프록시 호스트마다 토글 하나로 켜면 그 호스트의 도메인이 관리형 DDNS 레코드가 되어 도메인 변경 시 자동 동기화되고 호스트 삭제 시 함께 정리됩니다. 기존 호스트 일괄 등록과 갱신 주기 설정도 지원합니다.

Infomaniak을 사용하려면 먼저 [Infomaniak Manager](https://www.infomaniak.com/en/support/faq/2357/manage-a-dynamic-ip-with-infomaniak-dyndns)의 **Dynamic DNS**에서 각 호스트를 생성하세요. **인증서 > DNS 프로바이더**에서 **Infomaniak (DynDNS)**을 추가하고 전용 DynDNS 사용자 이름과 비밀번호(Manager 로그인이나 API 토큰 아님)를 입력한 뒤 DDNS 레코드 또는 프록시 호스트에서 선택하세요. 기존 IPv4/A 레코드만 갱신하며 원격 레코드 생성·삭제, TTL 변경, DNS-01 인증서는 지원하지 않습니다. 연결 테스트는 자격 증명 형식만 확인하며, 실제 갱신은 DDNS 동기화로 확인하세요.

### 🔐 ForwardAuth (v2.27.0)
프록시 호스트 앞에 **Authelia**, **Authentik** 또는 커스텀 `auth_request` 프로바이더를 두고, 호스트별 우회 경로를 지정할 수 있습니다. (한 호스트는 ForwardAuth와 지오/봇 챌린지 중 하나만 사용합니다.)

### 👥 다중 사용자 & 역할 (v2.34.0)
기본 제공 **관리자 / 운영자 / 뷰어** 역할과 영역별 읽기/쓰기 권한을 가진 커스텀 역할. 사용자마다 별도 계정과 2FA를 가지며, API 토큰은 발급자의 역할을 넘을 수 없습니다.

### 🪪 SSO / OIDC 로그인 (v2.35.0)
OpenID Connect 프로바이더(Keycloak 프리셋 포함)로 로그인. 비밀번호 로그인은 항상 유지되며, 자동 계정 생성은 허용 목록 없이는 거부됩니다.

### ☁️ Cloudflare Tunnel (v2.32.0, managed 모드 v2.48.0)
nginx 이미지에 `cloudflared`가 내장 — 터널 토큰만 붙여 넣으면 포트포워딩 없이 호스트가 외부에 노출되며, WAF/GeoIP/차단 스택은 그대로 통과합니다. managed 모드에서는 NPG가 터널의 catch-all 규칙을 대신 관리합니다.

### 🔔 알림 (v2.36.0)
Discord, Telegram, 범용 웹훅 채널. 10종 알림 각각을 끄기·즉시·일일 요약으로 설정할 수 있고, 일일 요약에는 CPU/메모리/디스크 상태도 포함됩니다.

### 🌐 전역 보안 기본값 (v2.31.0)
GeoIP 국가 제한, 봇 필터, 보안 헤더, 클라우드 제공자 차단, 요청 속도 제한, WAF 모드/Paranoia Level을 전역에서 한 번 설정하면 모든 호스트가 상속하거나 개별 재정의합니다.

### 🛰️ 신뢰 프록시 (v2.51.0)
Cloudflare나 다른 프록시 뒤에서 운영한다면 설정 → 신뢰 프록시(Cloudflare 프리셋 또는 커스텀 CIDR)로 실제 클라이언트 IP를 신뢰할 홉을 지정하세요. 차단, 접근 목록, GeoIP, fail2ban이 프록시가 아닌 방문자 IP에 대해 동작합니다.

### 🚧 전역 Fail2ban Jail (v2.53.0)
어떤 프록시 호스트에도 매칭되지 않은 요청(IP 직접 접근 스캐너, 미등록 호스트명 → 444)을 셉니다 — 호스트별 jail이 결코 볼 수 없는 트래픽입니다. 기본 비활성·Log-Only로 출시되며 신뢰 프록시 설정이 필요합니다.

그 외 6월 이후: 로그 필터 프리셋 저장(v2.33.0), 차단 IP별 활동 조회(v2.38.0), 앱 내 업데이트 확인(v2.29.0), 경로/인자 범위 WAF 룰 제외(v2.37.0, v2.54.0부터 완전 동작).

---

## 🛠 기술 스택

**견고한 기술 스택** - 현대적인 기술과 마이크로서비스 아키텍처로 설계

| 기술 | 용도 |
|------|------|
| **Nginx 1.30.4** | HTTP/3 & QUIC을 지원하는 고성능 HTTP 및 stream 리버스 프록시 코어 |
| **TimescaleDB (PostgreSQL 17)** | 로그 자동 압축을 위한 시계열 최적화 데이터베이스 |
| **Valkey 9** | Redis 호환 고속 캐싱 및 세션 관리 (선택) |
| **Go 1.26 (Echo v4)** | 효율적인 리소스 관리와 동시성 처리 백엔드 API |
| **React 19 & TypeScript 6** | 타입 안전성과 컴포넌트 기반의 모던 UI (Vite 8 + Tailwind 4) |
| **ModSecurity v3.0.15** | OWASP Core Rule Set v4.26.0 기반 웹 애플리케이션 방화벽 |
| **MaxMind GeoIP2** | 국가별 접근 제어를 위한 지리 IP 데이터베이스 |

---

## 🚀 빠른 시작

**1분 안에 시작하기** - Docker Compose로 Nginx Proxy Guard 실행

### 필요 조건

- Docker 24.0+ 및 Docker Compose v2
- linux/amd64 또는 linux/arm64 호스트 (Raspberry Pi 4/5 등 ARM64 서버 지원)
- (선택) GeoIP용 [MaxMind 라이선스 키](https://www.maxmind.com/en/geolite2/signup)

### 설치

```bash
# 1. 디렉토리 생성
mkdir -p ~/nginx-proxy-guard && cd ~/nginx-proxy-guard

# 2. 파일 다운로드
wget https://raw.githubusercontent.com/svrforum/nginxproxyguard/main/docker-compose.yml
wget -O .env https://raw.githubusercontent.com/svrforum/nginxproxyguard/main/env.example

# 3. 보안 시크릿 자동 생성
sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=$(openssl rand -base64 24)/" .env
sed -i "s/JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env

# 4. 서비스 시작
docker compose up -d
```

### 접속

| 서비스 | URL |
|--------|-----|
| 관리 패널 | https://localhost:81 |
| HTTP 프록시 | http://localhost:80 |
| HTTPS 프록시 | https://localhost:443 |

**기본 로그인**: `admin` / `admin` (첫 로그인 후 반드시 변경!)

> **보안 안내**
> - **v2.24.6**부터 기본 자격 증명을 변경하기 전까지 서버가 모든 보호 API를 차단합니다(초기 설정 게이트). 갓 설치된 인스턴스를 `admin`/`admin`으로 탈취할 수 없습니다.
> - **관리 패널(81 포트)을 인터넷에 노출하지 마세요.** LAN/VPN 안에 두거나, 액세스 리스트 + 2FA로 보호된 프록시 호스트 뒤에 두는 것을 권장합니다.
> - 취약점을 발견하셨나요? 공개 이슈 대신 비공개로 신고해주세요 — [SECURITY.md](./SECURITY.md) 참조.

> **비밀번호 정책 (v2.2.0+)**: 새 비밀번호는 최소 10자 이상이며, 대문자, 소문자, 숫자, 특수문자를 포함해야 합니다. 흔한 비밀번호는 차단됩니다.

### 업데이트

```bash
docker compose pull
docker compose up -d
```

### 관리자 비밀번호 초기화

비밀번호나 2FA 디바이스를 분실했을 때, 호스트 쉘 접근이 가능하다면 DB를 직접 건드리지 않고 CLI로 복구할 수 있습니다.

```bash
# admin 사용자가 한 명이면 자동으로 그 계정에 임의 비밀번호를 발급
docker compose exec api ./server reset-password

# 특정 사용자 지정
docker compose exec api ./server reset-password --username alice

# 임의 생성 대신 직접 비밀번호 지정 (8자 이상, 72바이트 이하)
docker compose exec api ./server reset-password --username alice --password 'S3cure-Pwd!'

# TOTP secret까지 같이 초기화하고 2FA 비활성화
docker compose exec api ./server reset-password --clear-2fa
```

성공 시 적용되는 사항:
- 새 bcrypt `password_hash` 기록
- 해당 사용자의 실패 `login_attempts` 정리 (IP 락아웃 회피)
- 해당 사용자의 모든 활성 `auth_session` 무효화 — 정상 사용자도, 토큰을 탈취한 누군가도 새 비밀번호로 다시 로그인해야 함
- `system_logs`에 `Password reset via CLI` 감사 항목 기록 (`source=audit`)

출력된 비밀번호로 로그인한 뒤, **계정 설정**에서 즉시 본인이 원하는 비밀번호로 다시 변경하세요.

### 업그레이드 안내

모든 버전은 완전히 하위 호환됩니다. 수동 마이그레이션 없이 시작 시 데이터베이스 스키마가 자동으로 업그레이드됩니다. 최신 이미지를 받아 컨테이너를 재생성하기만 하면 됩니다.

> **compose 수준의 새 옵션**(포트 재정의, API/로그인 속도 제한, `TRUSTED_PROXY_CIDR`, 컨테이너 로그 용량 제한, capability 제거)은 `docker-compose.yml`을 갱신한 설치에만 적용됩니다 — 이미지만 받으면 예전 compose 파일이 그대로 남습니다. 업그레이드 후 현재 [docker-compose.yml](./docker-compose.yml)과 비교하세요. 변경 내역은 [최신 릴리즈](https://github.com/svrforum/NginxProxyGuard/releases)와 [주요 기능](#-주요-기능)을 참조하세요.

---

## 📚 API 문서

Nginx Proxy Guard는 자동화 및 통합을 위한 포괄적인 REST API를 제공합니다.

### 인증

모든 API 엔드포인트는 다음을 통해 인증이 필요합니다:
- **세션 토큰**: `Authorization: Bearer <token>` (`POST /api/v1/auth/login` 응답의 `token` 필드, 2FA 사용 시에는 `POST /api/v1/auth/verify-2fa` 응답)
- **API 토큰**: `Authorization: Bearer ng_<api_token>` (자동화용)

### 주요 엔드포인트

| 엔드포인트 | 설명 |
|----------|------|
| `POST /api/v1/auth/login` | 인증 및 세션 토큰 획득 |
| `GET /api/v1/proxy-hosts` | 모든 프록시 호스트 목록 |
| `POST /api/v1/proxy-hosts` | 새 프록시 호스트 생성 |
| `GET /api/v1/certificates` | SSL 인증서 목록 |
| `POST /api/v1/certificates` | 새 인증서 요청 |
| `GET /api/v1/waf/rules` | WAF 규칙 목록 |
| `POST /api/v1/backups` | 백업 생성 |
| `GET /api/v1/filter-subscriptions` | 필터 구독 목록 |
| `GET /api/v1/dashboard` | 대시보드 통계 |

### Swagger UI

API 문서(Swagger UI)는 다음 주소에서 제공됩니다:
```
https://localhost:81/api/docs
```
원본 OpenAPI 3.0 스펙은 `https://localhost:81/api/docs/swagger.yaml`에서 받을 수 있습니다.

---

## ⚙️ 환경 변수

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `DB_PASSWORD` | PostgreSQL 비밀번호 | (필수) |
| `JWT_SECRET` | 애플리케이션 시크릿 — 무작위 값으로 설정 (`openssl rand -hex 32`) | `docker-compose.yml` 플레이스홀더 (변경 필요) |
| `TZ` | 시간대 | `UTC` |
| `DB_USER` | PostgreSQL 사용자 | `postgres` |
| `DB_NAME` | 데이터베이스 이름 | `nginx_proxy_guard` |
| `DOCKER_API_VERSION` | Docker API 버전 (시놀로지용) | 자동 감지 |
| `UI_PORT` | 관리 패널 호스트 포트 | `81` |
| `NGINX_HTTP_PORT` / `NGINX_HTTPS_PORT` | nginx 리슨 포트 (host 네트워크 모드; 80/443이 이미 사용 중일 때 변경, 예: Synology DSM) | `80` / `443` |
| `API_HOST_PORT` | nginx가 API에 접근하는 루프백 호스트 포트 (다른 서비스와 충돌 금지) | `9080` |
| `API_RATE_LIMIT_PER_MINUTE` | IP당 분당 API 요청 한도; `0` = 끔; Valkey 필요 | `600` |
| `AUTH_RATE_LIMIT_PER_MINUTE` | 로그인 엔드포인트 전용 IP당 분당 한도; `0` = 끔; Valkey 필요 | `100` |
| `TRUSTED_PROXY_CIDR` | API가 `X-Forwarded-For` 홉으로 신뢰할 CIDR(쉼표 구분); 미설정 = 루프백/링크로컬/사설망 전부 신뢰 | (미설정) |

---

## 📖 추가 정보

- **웹사이트**: [nginxproxyguard.com](https://nginxproxyguard.com)
- **문서**: [nginxproxyguard.com/docs](https://nginxproxyguard.com/ko/docs)

---

## ☕ 후원

Nginx Proxy Guard가 유용하셨다면, 프로젝트를 후원해주세요! [GitHub Sponsors](https://github.com/sponsors/svrforum)는 플랫폼 수수료가 없어 개발에 가장 직접적인 도움이 됩니다.

<a href="https://github.com/sponsors/svrforum" target="_blank"><img src="https://img.shields.io/badge/%E2%9D%A4%20GitHub%20Sponsors%EB%A1%9C%20%ED%9B%84%EC%9B%90-EA4AAA?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="GitHub Sponsors로 후원하기" height="50"></a>
<a href="https://buymeacoffee.com/svrforum" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50"></a>

---

## 📄 라이선스

이 프로젝트는 MIT 라이선스에 따라 배포됩니다 - 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 💬 지원

- [웹사이트](https://nginxproxyguard.com) - 문서 및 가이드
- [GitHub Issues](https://github.com/svrforum/nginxproxyguard/issues) - 버그 리포트 및 기능 요청
- [Discussions](https://github.com/svrforum/nginxproxyguard/discussions) - 질문 및 커뮤니티
- [GitHub Sponsors](https://github.com/sponsors/svrforum) - 프로젝트 후원 (수수료 없음)
- [Buy Me a Coffee](https://buymeacoffee.com/svrforum) - 프로젝트 후원

---

<div align="center">
  <sub>© 2025-2026 Nginx Proxy Guard. 강력하고 안전하고 빠른 Nginx 프록시 매니저 & WAF.</sub>
</div>
