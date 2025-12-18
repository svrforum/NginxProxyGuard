<div align="center">

# Nginx Proxy Guard

### 엔터프라이즈 보안을 갖춘 차세대 Nginx 리버스 프록시 매니저

[English](./README.md) | **한국어**

[![Nginx](https://img.shields.io/badge/Nginx-1.28.0-009639?style=for-the-badge&logo=nginx&logoColor=white)](https://nginx.org/)
[![ModSecurity](https://img.shields.io/badge/ModSecurity-v3.0.14-red?style=for-the-badge)](https://modsecurity.org/)
[![OWASP CRS](https://img.shields.io/badge/OWASP_CRS-v4.21.0-orange?style=for-the-badge)](https://coreruleset.org/)
[![HTTP/3](https://img.shields.io/badge/HTTP/3-QUIC-blue?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

<p align="center">
  <strong>강력한 WAF, 봇 보호, GeoIP 차단, Rate Limiting을 갖춘<br/>현대적인 리버스 프록시 관리 시스템</strong>
</p>

---

</div>

## ✨ 주요 기능

| 카테고리 | 기능 |
|----------|------|
| **WAF** | ModSecurity v3 + OWASP CRS v4.21, Paranoia Level 1-4, 호스트별 예외 설정 |
| **봇 보호** | 200+ 봇 시그니처, 검색엔진 허용목록, AI 봇 탐지 |
| **GeoIP** | 국가별 차단/챌린지, MaxMind 통합, 트래픽 시각화 |
| **Rate Limiting** | 호스트별/전역 제한, 버스트 처리, 자동 차단 |
| **챌린지** | reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile |
| **SSL/TLS** | Let's Encrypt 자동 갱신, HTTP/3 QUIC 지원 |
| **모니터링** | 실시간 대시보드, GeoIP 로그 뷰어, 트래픽 분석 |

---

## 🚀 빠른 시작

### 필요 조건

- Docker 24.0+ 및 Docker Compose v2
- (선택) GeoIP용 [MaxMind 라이선스 키](https://www.maxmind.com/en/geolite2/signup)

### 설치

```bash
# 1. 디렉토리 생성
mkdir -p ~/nginx-proxy-guard && cd ~/nginx-proxy-guard

# 2. 파일 다운로드
wget https://raw.githubusercontent.com/svrforum/nginxproxyguard/main/docker-compose.yml
wget -O .env https://raw.githubusercontent.com/svrforum/nginxproxyguard/main/.env.example

# 3. 보안 시크릿 자동 생성
sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=$(openssl rand -base64 24)/" .env
sed -i "s/JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env

# 4. 시간대 자동 감지
TZ=$(cat /etc/timezone 2>/dev/null || readlink /etc/localtime | sed 's|/usr/share/zoneinfo/||' 2>/dev/null || echo "UTC")
sed -i "s|TZ=.*|TZ=$TZ|" .env

# 5. 서비스 시작
docker compose up -d
```

### 접속

| 서비스 | URL |
|--------|-----|
| 관리 패널 | https://localhost:81 |
| HTTP 프록시 | http://localhost:80 |
| HTTPS 프록시 | https://localhost:443 |

**기본 로그인**: `admin` / `admin` (첫 로그인 후 반드시 변경!)

### 업데이트

```bash
docker compose pull
docker compose up -d
```

---

## 📚 문서

- [설정 가이드](./docs/configuration.md) - 환경 변수, SSL 설정, GeoIP
- [API 레퍼런스](./docs/api.md) - REST API 문서
- [아키텍처](./docs/architecture.md) - 시스템 설계 및 기술 스택
- [문제 해결](./docs/troubleshooting.md) - 일반적인 문제와 해결 방법
- [개발](./docs/development.md) - 기여 및 로컬 설정

---

## 📄 라이선스

이 프로젝트는 MIT 라이선스에 따라 라이선스가 부여됩니다 - 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 💬 지원

- [GitHub Issues](https://github.com/svrforum/nginxproxyguard/issues) - 버그 리포트 및 기능 요청
- [Discussions](https://github.com/svrforum/nginxproxyguard/discussions) - 질문 및 커뮤니티
