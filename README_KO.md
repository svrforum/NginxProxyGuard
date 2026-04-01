<div align="center">

# Nginx Proxy Guard

### Make Your Nginx Smarter & Safer

[English](./README.md) | **한국어**

<img src="./NPG_banner.png" alt="Nginx Proxy Guard" width="800">

[![Version](https://img.shields.io/badge/Version-2.7.0-brightgreen?style=for-the-badge)]()
[![Nginx](https://img.shields.io/badge/Nginx-1.28.0-009639?style=for-the-badge&logo=nginx&logoColor=white)](https://nginx.org/)
[![ModSecurity](https://img.shields.io/badge/ModSecurity-v3.0.14-red?style=for-the-badge)](https://modsecurity.org/)
[![OWASP CRS](https://img.shields.io/badge/OWASP_CRS-v4.21.0-orange?style=for-the-badge)](https://coreruleset.org/)
[![HTTP/3](https://img.shields.io/badge/HTTP/3-QUIC-blue?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

<p align="center">
  <strong>직관적인 웹 UI를 통해 프록시 호스트, SSL 인증서,<br/>보안 규칙을 관리할 수 있는 안전하고 빠른 솔루션</strong>
</p>

<p align="center">
  <a href="https://nginxproxyguard.com">웹사이트</a> •
  <a href="https://nginxproxyguard.com/ko/docs">문서</a> •
  <a href="#-주요-기능">기능</a> •
  <a href="#-빠른-시작">빠른 시작</a> •
  <a href="#-기술-스택">기술 스택</a> •
  <a href="#-api-문서">API</a> •
  <a href="https://buymeacoffee.com/svrforum">☕ 후원</a>
</p>

---

</div>

## ✨ 주요 기능

**강력한 보안, 쉬운 관리** - Nginx의 복잡함은 줄이고, 보안은 극대화

### 🔒 SSL 자동화
Let's Encrypt 통합 및 자동 갱신. DNS-01 챌린지를 통한 와일드카드 인증서 지원. **Cloudflare**, **DuckDNS**, **Dynu** 등 다양한 DNS 프로바이더 지원.

### 🤖 봇 보호
80개 이상의 악성 봇과 50개 이상의 AI 크롤러를 자동 차단. 검색 엔진 허용 목록으로 정상 트래픽 보장. 의심스러운 요청에 대한 CAPTCHA 챌린지 모드.

### 📊 직관적인 대시보드
실시간 트래픽 모니터링, 보안 차단 로그, 인증서 상태, 서버 상태를 한눈에 확인.

### 🌍 GeoIP 접근 제어
국가별 트래픽 차단/허용 및 인터랙티브 세계 지도 시각화. MaxMind GeoIP2 통합 및 자동 업데이트.

### 📝 로그 뷰어 & 분석
강력한 필터링과 제외 패턴으로 Nginx 접근/에러 로그 분석. **TimescaleDB** 시계열 최적화 및 자동 압축.

### 🛡️ 웹 애플리케이션 방화벽
ModSecurity v3 + OWASP Core Rule Set v4.21. Paranoia Level 1-4, 호스트별 룰 예외 처리, 익스플로잇 차단 규칙.

### ⚡ 요청 속도 제한
IP, URI, 또는 IP+URI 조합별 설정 가능한 속도 제한으로 DDoS 및 무차별 대입 공격 방어.

### 🔀 로드 밸런싱 & 업스트림
라운드 로빈, 최소 연결, IP 해시, 가중치 분산으로 다중 백엔드 서버 지원. 헬스 체크 포함.

### 🔐 보안 헤더
HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Content-Security-Policy.

### 📋 접근 목록
화이트리스트 또는 블랙리스트를 위한 IP 기반 접근 제어 목록. CIDR 표기법 지원.

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

---

## 🛠 기술 스택

**견고한 기술 스택** - 현대적인 기술과 마이크로서비스 아키텍처로 설계

| 기술 | 용도 |
|------|------|
| **Nginx 1.28** | HTTP/3 & QUIC 지원 고성능 리버스 프록시 코어 |
| **TimescaleDB** | 로그 압축을 위한 시계열 최적화 PostgreSQL |
| **Valkey 8** | Redis 호환 고속 캐싱 및 세션 관리 |
| **Go 1.24** | 효율적인 리소스 관리와 동시성 처리 백엔드 API |
| **React 18 & TypeScript** | 타입 안전성과 컴포넌트 기반의 모던 UI |
| **ModSecurity 3** | OWASP Core Rule Set v4.21 기반 웹 애플리케이션 방화벽 |
| **MaxMind GeoIP2** | 국가별 접근 제어를 위한 지리 IP 데이터베이스 |

---

## 🚀 빠른 시작

**1분 안에 시작하기** - Docker Compose로 Nginx Proxy Guard 실행

### 필요 조건

- Docker 24.0+ 및 Docker Compose v2
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

> **비밀번호 정책 (v2.2.0+)**: 새 비밀번호는 최소 10자 이상이며, 대문자, 소문자, 숫자, 특수문자를 포함해야 합니다. 흔한 비밀번호는 차단됩니다.

### 업데이트

```bash
docker compose pull
docker compose up -d
```

### v2.7.0 업그레이드 안내

모든 버전은 완전히 하위 호환됩니다. 수동 마이그레이션 없이 시작 시 데이터베이스 스키마가 자동으로 업그레이드됩니다.

> **v2.7.0 신규 기능**: 필터 구독 — 외부 IP 차단 목록을 구독하여 Nginx에 자동 동기화합니다. 자세한 내용은 [주요 기능](#-주요-기능)을 참조하세요.

---

## 📚 API 문서

Nginx Proxy Guard는 자동화 및 통합을 위한 포괄적인 REST API를 제공합니다.

### 인증

모든 API 엔드포인트는 다음을 통해 인증이 필요합니다:
- **JWT 토큰**: `Authorization: Bearer <jwt_token>` (로그인에서 획득)
- **API 토큰**: `Authorization: Bearer ng_<api_token>` (자동화용)

### 주요 엔드포인트

| 엔드포인트 | 설명 |
|----------|------|
| `POST /api/v1/auth/login` | 인증 및 JWT 토큰 획득 |
| `GET /api/v1/proxy-hosts` | 모든 프록시 호스트 목록 |
| `POST /api/v1/proxy-hosts` | 새 프록시 호스트 생성 |
| `GET /api/v1/certificates` | SSL 인증서 목록 |
| `POST /api/v1/certificates` | 새 인증서 요청 |
| `GET /api/v1/waf/rules` | WAF 규칙 목록 |
| `POST /api/v1/backups` | 백업 생성 |
| `GET /api/v1/filter-subscriptions` | 필터 구독 목록 |
| `GET /api/v1/dashboard` | 대시보드 통계 |

### Swagger UI

다음에서 대화형 API 문서에 접근하세요:
```
https://localhost:81/api/v1/swagger
```

---

## ⚙️ 환경 변수

| 변수 | 설명 | 기본값 |
|------|------|--------|
| `DB_PASSWORD` | PostgreSQL 비밀번호 | (필수) |
| `JWT_SECRET` | JWT 토큰용 시크릿 | (필수) |
| `TZ` | 시간대 | `UTC` |
| `DB_USER` | PostgreSQL 사용자 | `postgres` |
| `DB_NAME` | 데이터베이스 이름 | `nginx_proxy_guard` |
| `DOCKER_API_VERSION` | Docker API 버전 (시놀로지용) | 자동 감지 |

---

## 📖 추가 정보

- **웹사이트**: [nginxproxyguard.com](https://nginxproxyguard.com)
- **문서**: [nginxproxyguard.com/docs](https://nginxproxyguard.com/ko/docs)

---

## ☕ 후원

Nginx Proxy Guard가 유용하셨다면, 프로젝트를 후원해주세요!

<a href="https://buymeacoffee.com/svrforum" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50"></a>

---

## 📄 라이선스

이 프로젝트는 MIT 라이선스에 따라 배포됩니다 - 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 💬 지원

- [GitHub Issues](https://github.com/svrforum/nginxproxyguard/issues) - 버그 리포트 및 기능 요청
- [Discussions](https://github.com/svrforum/nginxproxyguard/discussions) - 질문 및 커뮤니티
- [Buy Me a Coffee](https://buymeacoffee.com/svrforum) - 프로젝트 후원

---

<div align="center">
  <sub>© 2025-2026 Nginx Proxy Guard. 강력하고 안전하고 빠른 Nginx 프록시 매니저 & WAF.</sub>
</div>
