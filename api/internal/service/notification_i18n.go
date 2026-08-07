package service

import "strings"

// Notification wording, per language (#221).
//
// The first version derived English text and called that a design decision on
// the grounds that "the server has no locale". That was a technical excuse: the
// person who configured the channel in Korean is the person who reads the
// alert, and sending them English is simply wrong. The language is now the
// channel's own setting, because one instance can legitimately post to a
// Korean team channel and an English one.
//
// This is a small hand-rolled table rather than a translation library. The
// vocabulary is fixed and tiny — nine events, three severities, a handful of
// field labels — and pulling in i18n machinery for it would cost more than it
// explains.

const (
	LangKorean  = "ko"
	LangEnglish = "en"
)

// SupportedNotificationLanguages is what the UI offers and Validate accepts.
var SupportedNotificationLanguages = []string{LangEnglish, LangKorean}

func normaliseLang(lang string) string {
	switch strings.ToLower(strings.TrimSpace(lang)) {
	case LangKorean, "ko-kr":
		return LangKorean
	default:
		return LangEnglish
	}
}

var notificationStrings = map[string]map[string]string{
	LangEnglish: {
		"severity.error":    "Problem",
		"severity.warning":  "Notice",
		"severity.info":     "Info",
		"severity.resolved": "Resolved",

		"event.cert.renewal_failed": "certificate renewal failed",
		"event.cert.renewed":        "certificate renewed",
		"event.ddns.sync_failed":    "DDNS update failed",
		"event.ddns.recovered":      "DDNS updating again",
		"event.backup.failed":       "scheduled backup failed",
		// Recovery titles for events whose recovery travels under the failure's
		// own key. Without them the headline reads "Resolved — backup failed".
		"event.backup.failed.resolved":       "scheduled backup working again",
		"event.nginx.reload_failed":          "nginx reload failed",
		"event.nginx.reload_failed.resolved": "nginx reloading again",
		"event.auth.login_failed":            "admin sign-in locked out",
		"event.ip.banned":                    "addresses banned",
		"event.sso.login_refused":            "SSO sign-in refused",
		"event.digest.daily":                 "daily summary",
		"event.test":                         "test notification",

		"field.host":     "host",
		"field.ip":       "address",
		"field.country":  "country",
		"field.count":    "count",
		"field.reason":   "reason",
		"field.detail":   "detail",
		"field.subject":  "subject",
		"field.time":     "time",
		"field.instance": "instance",

		"digest.title":         "Nginx Proxy Guard — last 24 hours",
		"digest.requests":      "Requests",
		"digest.hosts":         "Proxy hosts active",
		"digest.redirects":     "Redirects active",
		"digest.certificates":  "Certificates",
		"digest.bannedActive":  "Addresses currently banned",
		"digest.quiet":         "Nothing was blocked.",
		"digest.blocked":       "Blocked requests",
		"digest.topIPs":        "Most blocked addresses",
		"digest.overview":      "Overview",
		"digest.parked":        "Held for this summary",
		"digest.resources":     "Server resources",
		"digest.cpu":           "CPU",
		"digest.memory":        "Memory",
		"digest.disk":          "Disk",
		"digest.database":      "Database",
		"digest.uptime":        "Uptime",
		"unit.day":             "d",
		"unit.hour":            "h",
		"unit.minute":          "m",
		"digest.certs":         "Certificates expiring within 30 days",
		"digest.failing":       "Still failing",
		"digest.since":         "since",
		"digest.openDashboard": "Open the dashboard",
		"sample.test":          "This is a test from Nginx Proxy Guard.",
		"sample.certFail":      "DNS challenge timed out after 120s",
		"sample.certOK":        "valid for another 90 days",
		"sample.ddnsFail":      "provider rejected the update: invalid credentials",
		"sample.backup":        "no space left on device",
		"sample.nginx":         "nginx -t failed: duplicate location \"/\"",
		"sample.andMore":       "and 2 more",
		"footer.signature":     "Nginx Proxy Guard",
	},
	LangKorean: {
		"severity.error":    "문제",
		"severity.warning":  "주의",
		"severity.info":     "알림",
		"severity.resolved": "복구됨",

		"event.cert.renewal_failed":          "인증서 갱신 실패",
		"event.cert.renewed":                 "인증서 갱신 성공",
		"event.ddns.sync_failed":             "DDNS 갱신 실패",
		"event.ddns.recovered":               "DDNS 갱신 복구",
		"event.backup.failed":                "예약 백업 실패",
		"event.backup.failed.resolved":       "예약 백업 정상화",
		"event.nginx.reload_failed":          "nginx 리로드 실패",
		"event.nginx.reload_failed.resolved": "nginx 리로드 정상화",
		"event.auth.login_failed":            "관리자 로그인 잠금",
		"event.ip.banned":                    "IP 차단",
		"event.sso.login_refused":            "SSO 로그인 거부",
		"event.digest.daily":                 "일일 요약",
		"event.test":                         "테스트 알림",

		"field.host":     "호스트",
		"field.ip":       "주소",
		"field.country":  "국가",
		"field.count":    "건수",
		"field.reason":   "사유",
		"field.detail":   "상세",
		"field.subject":  "대상",
		"field.time":     "시각",
		"field.instance": "인스턴스",

		"digest.title":         "Nginx Proxy Guard — 최근 24시간",
		"digest.requests":      "요청 수",
		"digest.hosts":         "활성 프록시 호스트",
		"digest.redirects":     "활성 리다이렉트",
		"digest.certificates":  "인증서",
		"digest.bannedActive":  "현재 차단 중인 주소",
		"digest.quiet":         "차단된 요청이 없습니다.",
		"digest.blocked":       "차단된 요청",
		"digest.topIPs":        "가장 많이 차단된 주소",
		"digest.overview":      "현황",
		"digest.parked":        "요약으로 모아둔 알림",
		"digest.resources":     "서버 자원",
		"digest.cpu":           "CPU",
		"digest.memory":        "메모리",
		"digest.disk":          "디스크",
		"digest.database":      "데이터베이스",
		"digest.uptime":        "가동 시간",
		"unit.day":             "일",
		"unit.hour":            "시간",
		"unit.minute":          "분",
		"digest.certs":         "30일 내 만료 예정 인증서",
		"digest.failing":       "아직 복구되지 않음",
		"digest.since":         "시작",
		"digest.openDashboard": "대시보드 열기",
		"sample.test":          "Nginx Proxy Guard 테스트 알림입니다.",
		"sample.certFail":      "DNS 챌린지가 120초 후 시간 초과되었습니다",
		"sample.certOK":        "90일 더 유효합니다",
		"sample.ddnsFail":      "공급자가 갱신을 거부했습니다: 자격증명 오류",
		"sample.backup":        "디스크 공간이 부족합니다",
		"sample.nginx":         "nginx -t 실패: location \"/\" 중복",
		"sample.andMore":       "외 2건",
		"footer.signature":     "Nginx Proxy Guard",
	},
}

// tr looks up one string, falling back to English and then to the key itself so
// a missing entry degrades to something readable rather than to blank.
func tr(lang, key string) string {
	l := normaliseLang(lang)
	if v, ok := notificationStrings[l][key]; ok && v != "" {
		return v
	}
	if v, ok := notificationStrings[LangEnglish][key]; ok && v != "" {
		return v
	}
	return key
}
