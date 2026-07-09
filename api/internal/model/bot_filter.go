package model

import "time"

// BotFilter represents bot filtering configuration for a proxy host
type BotFilter struct {
	ID                      string    `json:"id"`
	ProxyHostID             string    `json:"proxy_host_id"`
	Enabled                 bool      `json:"enabled"`
	BlockBadBots            bool      `json:"block_bad_bots"`
	BlockAIBots             bool      `json:"block_ai_bots"`
	AllowSearchEngines      bool      `json:"allow_search_engines"`
	BlockSuspiciousClients  bool      `json:"block_suspicious_clients"`
	CustomBlockedAgents     string    `json:"custom_blocked_agents,omitempty"`
	CustomAllowedAgents     string    `json:"custom_allowed_agents,omitempty"`
	ChallengeSuspicious     bool      `json:"challenge_suspicious"`
	DisableGlobal           bool      `json:"disable_global"` // opt out of global bot filter default (#198)
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// CreateBotFilterRequest is the request to create/update bot filter config
type CreateBotFilterRequest struct {
	Enabled                 *bool  `json:"enabled,omitempty"`
	BlockBadBots            *bool  `json:"block_bad_bots,omitempty"`
	BlockAIBots             *bool  `json:"block_ai_bots,omitempty"`
	AllowSearchEngines      *bool  `json:"allow_search_engines,omitempty"`
	BlockSuspiciousClients  *bool  `json:"block_suspicious_clients,omitempty"`
	CustomBlockedAgents     string `json:"custom_blocked_agents,omitempty"`
	CustomAllowedAgents     string `json:"custom_allowed_agents,omitempty"`
	ChallengeSuspicious     *bool  `json:"challenge_suspicious,omitempty"`
	DisableGlobal           *bool  `json:"disable_global,omitempty"`
}

// GlobalBotFilter is the singleton global bot-filter default inherited by hosts
// that don't override or disable (#198).
type GlobalBotFilter struct {
	ID                     string    `json:"id"`
	Enabled                bool      `json:"enabled"`
	BlockBadBots           bool      `json:"block_bad_bots"`
	BlockAIBots            bool      `json:"block_ai_bots"`
	AllowSearchEngines     bool      `json:"allow_search_engines"`
	BlockSuspiciousClients bool      `json:"block_suspicious_clients"`
	CustomBlockedAgents    string    `json:"custom_blocked_agents,omitempty"`
	CustomAllowedAgents    string    `json:"custom_allowed_agents,omitempty"`
	ChallengeSuspicious    bool      `json:"challenge_suspicious"`
	CreatedAt              time.Time `json:"created_at"`
	UpdatedAt              time.Time `json:"updated_at"`
}

// UpdateGlobalBotFilterRequest is a partial update for the global bot-filter singleton.
type UpdateGlobalBotFilterRequest struct {
	Enabled                *bool   `json:"enabled,omitempty"`
	BlockBadBots           *bool   `json:"block_bad_bots,omitempty"`
	BlockAIBots            *bool   `json:"block_ai_bots,omitempty"`
	AllowSearchEngines     *bool   `json:"allow_search_engines,omitempty"`
	BlockSuspiciousClients *bool   `json:"block_suspicious_clients,omitempty"`
	CustomBlockedAgents    *string `json:"custom_blocked_agents,omitempty"`
	CustomAllowedAgents    *string `json:"custom_allowed_agents,omitempty"`
	ChallengeSuspicious    *bool   `json:"challenge_suspicious,omitempty"`
}

// Known bad bots user agent patterns (Updated: December 2025)
// NOTE: Korean search engines (Yeti, NaverBot, Daum) moved to SearchEngineBots
var KnownBadBots = []string{
	// === SEO & Backlink Analysis Tools ===
	// These commercial bots provide no benefit to home servers
	"AhrefsBot",
	"SemrushBot",
	"DotBot",
	"MJ12bot",
	"BLEXBot",
	"DataForSeoBot",
	"serpstatbot",
	"SerpstatBot",
	"AspiegelBot",
	"BacklinkCrawler",
	"Exabot",
	"MegaIndex",
	"LinkpadBot",
	"PetalBot",      // Huawei - aggressive
	"SeznamBot",     // Czech search engine
	"Rogerbot",
	"PaperLiBot",
	"BomboraBot",
	"SEOkicks",
	"ZoominfoBot",
	"Barkrowler",
	"TurnitinBot", // Plagiarism checker
	"Seekport Crawler",
	"MauiBot",

	// === Content Scrapers ===
	"Xenu Link Sleuth",
	"Screaming Frog SEO Spider",
	"HTTrack",
	"WebCopier",
	"SiteSnagger",
	"ProWebWalker",
	"CheeseBot",
	"LinkExtractorPro",
	"CopyRightCheck",
	"Siphon",
	"EmailSiphon",
	"EmailWolf",
	"ExtractorPro",
	"Harvest",
	"Collector",
	"NetMechanic",
	"WebReaper",
	"Zeus",

	// === Archive Bots ===
	"Nutch",
	"Heritrix",
	"ia_archiver",
	"archive.org_bot",

	// === Aggressive Regional Crawlers ===
	// (Korean Yeti/NaverBot/Daum moved to allowed list)
	"Mail.RU_Bot",
	"360Spider",     // Qihoo 360 (China)
	"YisouSpider",   // China
	"JikeSpider",    // China
	"EasouSpider",   // China
	"Sogou",         // China - aggressive
	"Baiduspider",   // China - block unless targeting Chinese audience
	"Ezooms",
	"discobot",
	"TweetmemeBot",
	"Qwantify",
	"Gigabot",
	"Speedy Spider",
	"findlinks",
	"Lipperhey",
	"Cliqzbot",
	"DomainStatsBot",
	"NetcraftSurveyAgent",

	// === Security Scanners & Hacking Tools ===
	"censys",
	"masscan",
	"ZmEu",
	"Morfeus",
	"Nikto",
	"Nmap",
	"sqlmap",
	"WPScan",
	"Acunetix",
	"AppSpider",
	"Nessus",
	"OpenVAS",
	"w3af",
	"Havij",
	"zgrab",
	"Nimbostratus",
	"WinHttp", // Windows HTTP library - usually not a real browser
}

// SuspiciousClients are HTTP client libraries that may or may not be malicious
// These are legitimate tools but often used for scraping - use with caution
var SuspiciousClients = []string{
	// CLI tools
	"curl",
	"Wget",
	// Perl
	"libwww-perl",
	// Python
	"python-requests",
	"Python-urllib",
	"Python-httpx",
	"httpx",
	"aiohttp",
	// Java
	"Java",
	"Apache-HttpClient",
	"okhttp",
	// Go
	"Go-http-client",
	"Go-http",
	// Node.js
	"node-fetch",
	"axios",
	"got",
	// Generic
	"http_requester",
	"HttpClient",
	"request",
	"fetch",
	"urllib",
	"http.client",
	"requests",
	// Scraping frameworks
	"scrapy",
	"mechanize",
	// Headless browsers
	"phantom",
	"headless",
	"puppeteer",
	"playwright",
	"selenium",
	"chromedriver",
	"geckodriver",
}

// AI crawler bots for training/research (Updated: December 2025)
// NOTE: ChatGPT-User moved to SearchEngineBots (user browsing feature)
// NOTE: facebookexternalhit moved to SearchEngineBots (link preview)
// NOTE: Google-Extended removed (only controllable via robots.txt, not User-Agent)
var AIBots = []string{
	// === OpenAI ===
	"GPTBot", // AI training crawler (block)
	"OAI-SearchBot",

	// === Anthropic ===
	"ClaudeBot",
	"Claude-Web",
	"Claude-User",
	"Claude-SearchBot",
	"anthropic-ai",

	// === Common Crawl ===
	"CCBot", // Used by most AI companies for training data

	// === Google AI ===
	// Google-Extended is NOT a User-Agent, use robots.txt instead
	"Google-CloudVertexBot",
	"GoogleOther", // Google R&D purposes
	"Gemini-Deep-Research",
	"GoogleAgent-Mariner",
	"Google-NotebookLM",

	// === Meta AI ===
	"Meta-ExternalAgent",
	"Meta-ExternalFetcher",
	"FacebookBot", // Meta AI training (different from facebookexternalhit)

	// === Amazon ===
	"Amazonbot", // Amazon search/AI
	"AmazonBuyForMe",
	"amazon-kendra",

	// === Apple AI ===
	"Applebot-Extended", // AI training (different from search Applebot)

	// === ByteDance/TikTok ===
	"Bytespider", // VERY aggressive, definitely block
	"TikTokSpider",

	// === Perplexity ===
	"PerplexityBot",
	"Perplexity-User",

	// === Cohere ===
	"cohere-ai",
	"cohere-training-data-crawler",

	// === DeepSeek ===
	"DeepSeekBot",

	// === Other AI Crawlers ===
	"YouBot",
	"Diffbot",
	"DuckAssistBot",
	"PanguBot",
	"Timpibot",
	"Webzio-Extended",
	"FirecrawlAgent",
	"ImagesiftBot",
	"AI2Bot",
	"AI2Bot-Dolma",
	"Ai2Bot-DeepResearchEval",
	"Bravebot",
	"iAskBot",
	"iaskspider",
	"PhindBot",
	"ChatGLM-Spider",
	"WRTNBot",
	"SBIntuitionsBot",
	"MistralAI-User",
	"LinerBot",
	"Manus-User",
	"NovaAct",
	"Operator",
	"Crawl4AI",
	"bedrockbot",
	"img2dataset",
	"Omgilibot", // Aggressive market research bot
}

// Search engine bots (usually allowed) - Updated: December 2025
// These bots are essential for SEO and SNS link previews
var SearchEngineBots = []string{
	// === Google (2025 Complete List) ===
	"Googlebot",
	"Googlebot-Image",
	"Googlebot-Video",
	"Googlebot-News",
	"Googlebot-Mobile",
	"Google-InspectionTool",
	"Storebot-Google",
	"APIs-Google",
	"AdsBot-Google",
	"AdsBot-Google-Mobile",
	"AdsBot-Google-Mobile-Apps",
	"Google-AdsTxt",
	"Mediapartners-Google",
	"Feedfetcher-Google",
	"Google-Site-Verification",
	"Google-Read-Aloud",
	"Google-Adwords-Instant",
	"Google Favicon",
	"googleweblight",

	// === Microsoft Bing (2025 Complete List) ===
	"bingbot",
	"BingPreview",
	"msnbot",
	"msnbot-media",
	"adidxbot",
	"MicrosoftPreview",

	// === DuckDuckGo ===
	"DuckDuckBot",
	"DuckDuckGo-Favicons-Bot",

	// === Yahoo ===
	"Slurp",
	"Yahoo Ad monitoring",
	"Yahoo Link Preview",

	// === Apple Search ===
	"Applebot", // Search only (Applebot-Extended is for AI training)

	// === Korean Search Engines (ESSENTIAL for Korean sites) ===
	"Yeti",              // Naver main crawler
	"NaverBot",          // Naver legacy crawler
	"Daum",              // Daum/Kakao crawler
	"Daumoa",            // Daum legacy crawler
	"Naver Blog Rssbot", // Naver blog RSS

	// === SNS Link Preview Bots (ESSENTIAL for sharing) ===
	"kakaotalk-scrap",        // KakaoTalk URL preview
	"facebookexternalhit",    // Facebook/Instagram/Kakao link preview
	"Twitterbot",             // X/Twitter
	"LinkedInBot",            // LinkedIn
	"facebot",                // Facebook
	"WhatsApp",               // WhatsApp
	"TelegramBot",            // Telegram
	"Discordbot",             // Discord
	"Slackbot",               // Slack
	"Slackbot-LinkExpanding", // Slack link expansion
	"Pinterest",              // Pinterest
	"Pinterestbot",           // Pinterest
	"Embedly",                // Embed.ly
	"Quora Link Preview",     // Quora
	"vkShare",                // VK
	"Viber",                  // Viber
	"Line",                   // Line messenger

	// === User Browsing Agents (NOT AI training) ===
	"ChatGPT-User", // User's browsing feature in ChatGPT

	// === Yandex (Russian - 2025 Complete) ===
	"Yandex",
	"YandexBot",
	"YandexImages",
	"YandexVideo",
	"YandexMedia",
	"YandexBlogs",
	"YandexNews",
	"YandexPagechecker",
	"YandexMetrika",
	"YandexWebmaster",
	"YandexMobileBot",

	// === Other Search Engines ===
	"Baiduspider-render", // Baidu rendering
	"Qwant",              // French search engine
	"Ecosia",             // Eco-friendly search
	"mojeek",             // Privacy-focused search
	"seznambot",          // Czech search engine
}
