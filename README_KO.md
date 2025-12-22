<div align="center">

# Nginx Proxy Guard

### Make Your Nginx Smarter & Safer

[English](./README.md) | **한국어**

<img src="./NPG_banner.png" alt="Nginx Proxy Guard" width="800">

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
  <a href="#-주요-기능">기능</a> •
  <a href="#-빠른-시작">빠른 시작</a> •
  <a href="#-기술-스택">기술 스택</a>
</p>

---

</div>

## ✨ 주요 기능

**강력한 보안, 쉬운 관리** - Nginx의 복잡함은 줄이고, 보안은 극대화

### SSL 자동화
Let's Encrypt 통합 및 자동 갱신. DNS-01 챌린지(Cloudflare)를 통한 와일드카드 인증서 지원.

### 봇 보호
80개 이상의 악성 봇과 50개 이상의 AI 크롤러를 자동 차단. 검색 엔진 허용 목록으로 정상 트래픽 보장.

### 직관적인 대시보드
실시간 트래픽 모니터링, 차단 로그, 서버 상태를 한눈에 확인.

### GeoIP 접근 제어
국가별 트래픽 차단/허용 및 인터랙티브 지도 시각화. MaxMind GeoIP2 통합.

### 로그 뷰어 & 분석
강력한 필터링과 제외 패턴으로 Nginx 접근/에러 로그 분석.

### 웹 애플리케이션 방화벽
ModSecurity v3 + OWASP Core Rule Set v4.21. Paranoia Level 1-4, 호스트별 룰 예외 처리.

---

## 🛠 기술 스택

**견고한 기술 스택** - 현대적인 기술과 마이크로서비스 아키텍처로 설계

| 기술 | 용도 |
|------|------|
| **Nginx** | HTTP/3 & QUIC 지원 고성능 리버스 프록시 코어 |
| **PostgreSQL** | 설정 및 로그 데이터의 안전한 저장, 쿼리 최적화 |
| **Valkey (Redis)** | 고속 캐싱, 세션 관리, 실시간 데이터 처리 |
| **Go (Golang)** | 효율적인 리소스 관리와 동시성 처리 백엔드 API |
| **React & TypeScript** | 타입 안전성과 컴포넌트 기반의 모던 UI |
| **ModSecurity** | OWASP Core Rule Set 기반 웹 애플리케이션 방화벽 |

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

### 업데이트

```bash
docker compose pull
docker compose up -d
```

---

## 📖 추가 정보

- **웹사이트**: [nginxproxyguard.com](https://nginxproxyguard.com)
- **문서**: [nginxproxyguard.com/docs](https://nginxproxyguard.com/ko/docs)

---

## 📄 라이선스

이 프로젝트는 MIT 라이선스에 따라 배포됩니다 - 자세한 내용은 [LICENSE](LICENSE) 파일을 참조하세요.

## 💬 지원

- [GitHub Issues](https://github.com/svrforum/nginxproxyguard/issues) - 버그 리포트 및 기능 요청
- [Discussions](https://github.com/svrforum/nginxproxyguard/discussions) - 질문 및 커뮤니티

---

<div align="center">
  <sub>© 2025 Nginx Proxy Guard. 강력하고 안전하고 빠른 Nginx 프록시 매니저 & WAF.</sub>
</div>
