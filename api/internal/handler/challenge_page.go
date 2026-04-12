package handler

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/service"
)

// GetChallengePage returns the challenge page HTML (public endpoint)
func (h *ChallengeHandler) GetChallengePage(c echo.Context) error {
	proxyHostID := c.QueryParam("host")
	reason := c.QueryParam("reason")

	if reason == "" {
		reason = "geo_restriction"
	}

	var proxyHostPtr *string
	if proxyHostID != "" {
		proxyHostPtr = &proxyHostID
	}

	data, err := h.svc.GenerateChallengePageData(c.Request().Context(), proxyHostPtr, reason)
	if err != nil {
		if err == service.ErrChallengeDisabled {
			return c.HTML(http.StatusForbidden, `<!DOCTYPE html><html><head><title>Access Denied</title></head><body><h1>Access Denied</h1><p>Your request has been blocked.</p></body></html>`)
		}
		return c.HTML(http.StatusInternalServerError, `<!DOCTYPE html><html><head><title>Error</title></head><body><h1>Error</h1><p>An error occurred.</p></body></html>`)
	}

	// Return challenge page HTML
	html := generateChallengePageHTML(data)
	return c.HTML(http.StatusOK, html)
}

// generateChallengePageHTML generates the HTML for challenge page with i18n support
func generateChallengePageHTML(data map[string]interface{}) string {
	siteKey := data["site_key"].(string)
	challengeType := data["challenge_type"].(string)
	theme := data["theme"].(string)
	pageTitle := data["page_title"].(string)
	pageMessage := data["page_message"].(string)
	reason := data["reason"].(string)

	proxyHostID := ""
	if v, ok := data["proxy_host_id"].(*string); ok && v != nil {
		proxyHostID = *v
	}

	// Admin-configured default language ('auto' | 'ko' | 'en'). Resolved by the
	// service, falls back to 'auto' when system_settings is unavailable.
	errorPageLanguage := "auto"
	if v, ok := data["error_page_language"].(string); ok && v != "" {
		errorPageLanguage = v
	}

	// Determine script and widget based on challenge type
	// Use escapeHTML to prevent XSS attacks from malicious siteKey values
	var captchaScript, captchaWidget string
	safeSiteKey := escapeHTML(siteKey)
	safeTheme := escapeHTML(theme)

	switch challengeType {
	case "turnstile":
		captchaScript = `<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>`
		captchaWidget = `<div class="cf-turnstile" data-sitekey="` + safeSiteKey + `" data-theme="` + safeTheme + `" data-callback="onCaptchaSuccess"></div>`
	case "recaptcha_v3":
		captchaScript = `<script src="https://www.google.com/recaptcha/api.js?render=` + safeSiteKey + `"></script>`
		captchaWidget = `<div id="recaptcha-v3-notice" data-i18n="verifying"></div>`
	default: // recaptcha_v2
		captchaScript = `<script src="https://www.google.com/recaptcha/api.js" async defer></script>`
		captchaWidget = `<div class="g-recaptcha" data-sitekey="` + safeSiteKey + `" data-theme="` + safeTheme + `" data-callback="onCaptchaSuccess"></div>`
	}

	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>` + escapeHTML(pageTitle) + ` - Nginx Proxy Guard</title>
    <link rel="icon" type="image/x-icon" href="/favicon.ico">
    ` + captchaScript + `
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background: ` + getBackgroundColor(theme) + `;
            color: ` + getTextColor(theme) + `;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        .container {
            background: ` + getCardColor(theme) + `;
            border-radius: 16px;
            padding: 40px;
            max-width: 480px;
            width: 100%;
            text-align: center;
            box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1), 0 2px 4px -1px rgba(0, 0, 0, 0.06);
        }
        .logo {
            width: 80px;
            height: 80px;
            margin: 0 auto 24px;
        }
        .logo img { width: 100%; height: 100%; object-fit: contain; }
        .brand { font-size: 0.75rem; color: ` + getSubtextColor(theme) + `; margin-bottom: 20px; letter-spacing: 0.5px; }
        h1 { font-size: 1.5rem; margin-bottom: 12px; font-weight: 600; }
        p.message { color: ` + getSubtextColor(theme) + `; margin-bottom: 28px; line-height: 1.6; font-size: 0.95rem; }
        .g-recaptcha, .cf-turnstile { display: inline-block; margin-bottom: 20px; }
        #recaptcha-v3-notice { padding: 16px; background: ` + getNoticeBackground(theme) + `; border-radius: 8px; margin-bottom: 20px; color: ` + getSubtextColor(theme) + `; }
        .error { color: #ef4444; margin-top: 12px; display: none; font-size: 0.9rem; }
        .success { color: #22c55e; margin-top: 12px; display: none; font-size: 0.9rem; }
        .manual-link { display: none; margin-top: 16px; }
        .manual-link a { color: #3b82f6; text-decoration: underline; font-size: 0.9rem; }
        .loading { display: none; margin-top: 12px; }
        .spinner {
            border: 3px solid ` + getSpinnerBg(theme) + `;
            border-top: 3px solid #3b82f6;
            border-radius: 50%;
            width: 24px;
            height: 24px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }
        @keyframes spin { 0% { transform: rotate(0deg); } 100% { transform: rotate(360deg); } }
        .footer { margin-top: 28px; font-size: 0.8rem; color: ` + getSubtextColor(theme) + `; line-height: 1.5; }
        .lang-switch { margin-top: 16px; }
        .lang-switch button {
            background: transparent;
            border: 1px solid ` + getLangBtnBorder(theme) + `;
            color: ` + getSubtextColor(theme) + `;
            padding: 4px 12px;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.75rem;
            margin: 0 4px;
            transition: all 0.2s;
        }
        .lang-switch button:hover { background: ` + getLangBtnHover(theme) + `; }
        .lang-switch button.active { background: #3b82f6; color: white; border-color: #3b82f6; }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <img src="/api/v1/challenge/favicon.ico" alt="Nginx Proxy Guard">
        </div>
        <div class="brand">NGINX PROXY GUARD</div>
        <h1 id="title">` + escapeHTML(pageTitle) + `</h1>
        <p class="message" id="message">` + escapeHTML(pageMessage) + `</p>

        ` + captchaWidget + `

        <div class="loading"><div class="spinner"></div></div>
        <div class="error" id="error"></div>
        <div class="success" id="success"></div>
        <div class="manual-link" id="manual-link"><a id="manual-link-a" href="/"></a></div>

        <div class="footer">
            <span id="footer-text"></span>
        </div>

        <div class="lang-switch">
            <button onclick="setLang('ko')" id="lang-ko">한국어</button>
            <button onclick="setLang('en')" id="lang-en">English</button>
        </div>
    </div>

    <script>
        const proxyHostId = '` + escapeJS(proxyHostID) + `';
        const reason = '` + escapeJS(reason) + `';
        const challengeType = '` + escapeJS(challengeType) + `';

        // i18n translations
        const i18n = {
            ko: {
                title: '보안 확인',
                message: '계속하려면 아래 보안 확인을 완료해주세요.',
                verifying: '확인 중...',
                success: '인증 완료! 이동 중...',
                error: '인증에 실패했습니다. 다시 시도해주세요.',
                networkError: '오류가 발생했습니다. 다시 시도해주세요.',
                footer: '이 보안 확인은 자동화된 접근으로부터 보호합니다.',
                manualRedirect: '자동 이동되지 않으면 여기를 클릭하세요'
            },
            en: {
                title: 'Security Check',
                message: 'Please complete the security check below to continue.',
                verifying: 'Verifying...',
                success: 'Verified! Redirecting...',
                error: 'Verification failed. Please try again.',
                networkError: 'An error occurred. Please try again.',
                footer: 'This security check helps protect against automated access.',
                manualRedirect: 'Click here if you are not redirected automatically'
            }
        };

        // Admin-configured global default ('auto' | 'ko' | 'en'), injected by the server.
        const adminDefaultLang = '` + escapeJS(errorPageLanguage) + `';

        // Resolve language using the same priority as /403.html:
        //   1. Visitor's explicit click (localStorage)
        //   2. Admin-configured global default (if not 'auto')
        //   3. Browser language, with English fallback for unsupported locales
        function detectLang() {
            const saved = localStorage.getItem('npg_lang');
            if (saved && i18n[saved]) return saved;
            if (i18n[adminDefaultLang]) return adminDefaultLang;
            const browserLang = navigator.language.split('-')[0];
            return i18n[browserLang] ? browserLang : 'en';
        }

        let currentLang = detectLang();

        function setLang(lang) {
            currentLang = lang;
            localStorage.setItem('npg_lang', lang);
            document.documentElement.lang = lang;
            updateTexts();
            document.querySelectorAll('.lang-switch button').forEach(btn => btn.classList.remove('active'));
            document.getElementById('lang-' + lang).classList.add('active');
        }

        function t(key) {
            return i18n[currentLang][key] || i18n['en'][key] || key;
        }

        function updateTexts() {
            document.getElementById('title').textContent = t('title');
            document.getElementById('message').textContent = t('message');
            document.getElementById('footer-text').textContent = t('footer');
            document.getElementById('success').textContent = t('success');
            const v3Notice = document.getElementById('recaptcha-v3-notice');
            if (v3Notice) v3Notice.textContent = t('verifying');
        }

        // Initialize
        document.documentElement.lang = currentLang;
        updateTexts();
        document.getElementById('lang-' + currentLang).classList.add('active');

        function showError(msg) {
            document.getElementById('error').textContent = msg || t('error');
            document.getElementById('error').style.display = 'block';
            document.querySelector('.loading').style.display = 'none';
        }

        function showSuccess() {
            document.getElementById('success').textContent = t('success');
            document.getElementById('success').style.display = 'block';
            document.querySelector('.loading').style.display = 'none';
        }

        function showLoading() {
            document.querySelector('.loading').style.display = 'block';
            document.getElementById('error').style.display = 'none';
        }

        async function verifyCaptcha(token) {
            showLoading();

            try {
                const response = await fetch('/api/v1/challenge/verify', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        token: token,
                        proxy_host_id: proxyHostId,
                        challenge_reason: reason
                    })
                });

                const data = await response.json();

                if (data.success) {
                    const expires = new Date(data.expires_at).toUTCString();
                    const securePart = window.location.protocol === 'https:' ? '; Secure' : '';
                    document.cookie = 'ng_challenge=' + data.token + '; path=/; expires=' + expires + '; SameSite=Lax' + securePart;

                    showSuccess();

                    // Extract return URL: use substring instead of URLSearchParams
                    // because the return URL may contain '&' (unencoded query params)
                    // and 'return=' is always the last parameter in the redirect URL.
                    const search = window.location.search;
                    const returnIdx = search.indexOf('return=');
                    const returnUrl = returnIdx !== -1 ? search.substring(returnIdx + 7) : '/';

                    // Show manual redirect link after 3s as fallback
                    setTimeout(() => {
                        const linkEl = document.getElementById('manual-link');
                        const linkA = document.getElementById('manual-link-a');
                        linkA.href = returnUrl;
                        linkA.textContent = t('manualRedirect');
                        linkEl.style.display = 'block';
                    }, 3000);

                    setTimeout(() => {
                        window.location.href = returnUrl;
                    }, 1000);
                } else {
                    showError(data.error || t('error'));
                    if (typeof grecaptcha !== 'undefined' && challengeType === 'recaptcha_v2') {
                        grecaptcha.reset();
                    }
                }
            } catch (err) {
                showError(t('networkError'));
                console.error(err);
            }
        }

        function onCaptchaSuccess(token) {
            verifyCaptcha(token);
        }

        if (challengeType === 'recaptcha_v3') {
            grecaptcha.ready(function() {
                grecaptcha.execute('` + siteKey + `', {action: 'challenge'}).then(function(token) {
                    verifyCaptcha(token);
                });
            });
        }
    </script>
</body>
</html>`
}

func getNoticeBackground(theme string) string {
	if theme == "dark" {
		return "#1e293b"
	}
	return "#f1f5f9"
}

func getSpinnerBg(theme string) string {
	if theme == "dark" {
		return "#475569"
	}
	return "#f3f3f3"
}

func getLangBtnBorder(theme string) string {
	if theme == "dark" {
		return "#475569"
	}
	return "#e2e8f0"
}

func getLangBtnHover(theme string) string {
	if theme == "dark" {
		return "#475569"
	}
	return "#f1f5f9"
}

func getBackgroundColor(theme string) string {
	if theme == "dark" {
		return "#1e293b"
	}
	return "#f8fafc"
}

func getTextColor(theme string) string {
	if theme == "dark" {
		return "#f1f5f9"
	}
	return "#1e293b"
}

func getCardColor(theme string) string {
	if theme == "dark" {
		return "#334155"
	}
	return "#ffffff"
}

func getSubtextColor(theme string) string {
	if theme == "dark" {
		return "#94a3b8"
	}
	return "#64748b"
}
