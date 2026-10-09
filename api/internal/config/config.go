package config

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port            string
	DatabaseURL     string
	RedisURL        string
	JWTSecret       string
	Environment     string
	NginxConfigPath string
	NginxCertsPath  string
	NginxContainer  string
	ACMEEmail       string
	ACMEStaging     bool
	LogCollection   bool
	BackupPath      string
	DBMaxOpenConns  int
	DBMaxIdleConns  int

	// Raw log archive (service.RawLogArchiver). The directory is fixed by the
	// operator's mount, never by the database: it is where the archive share
	// is bound inside the API container, and NPG never creates it — a missing
	// directory is how "not mounted" is detected.
	RawLogArchiveDir string
	// How long a rotated file must be left alone before it moves (0 in e2e).
	RawLogArchiveSettle time.Duration
}

func Load() *Config {
	// Load .env file if exists
	godotenv.Load()

	cfg := &Config{
		Port:            getEnv("PORT", "8080"),
		DatabaseURL:     getEnv("DATABASE_URL", "postgres://postgres:postgres@db:5432/nginx_proxy_guard?sslmode=disable"),
		RedisURL:        getEnv("REDIS_URL", ""),
		JWTSecret:       getEnv("JWT_SECRET", "your-secret-key-change-in-production"),
		Environment:     getEnv("ENVIRONMENT", "development"),
		NginxConfigPath: getEnv("NGINX_CONFIG_PATH", "/etc/nginx/conf.d"),
		NginxCertsPath:  getEnv("NGINX_CERTS_PATH", "/etc/nginx/certs"),
		NginxContainer:  getEnv("NGINX_CONTAINER", "npg-proxy"),
		ACMEEmail:       getEnv("ACME_EMAIL", ""),
		ACMEStaging:     getEnv("ACME_STAGING", "true") == "true",
		LogCollection:   getEnv("LOG_COLLECTION", "true") == "true",
		BackupPath:      getEnv("BACKUP_PATH", "/data/backups"),
		DBMaxOpenConns:  getEnvInt("NPG_DB_MAX_OPEN", 80),
		DBMaxIdleConns:  getEnvInt("NPG_DB_MAX_IDLE", 20),

		RawLogArchiveDir:    getEnv("NPG_RAW_LOG_ARCHIVE_DIR", "/archive"),
		RawLogArchiveSettle: getEnvDuration("NPG_RAW_LOG_ARCHIVE_SETTLE", 10*time.Minute),
	}

	// database/sql silently clamps MaxIdleConns to MaxOpenConns when the
	// former exceeds the latter, swallowing the operator's misconfiguration.
	// Surface it explicitly so misconfigured envs are visible at startup.
	if cfg.DBMaxIdleConns > cfg.DBMaxOpenConns {
		log.Printf("[config] NPG_DB_MAX_IDLE (%d) > NPG_DB_MAX_OPEN (%d) — clamping idle to open", cfg.DBMaxIdleConns, cfg.DBMaxOpenConns)
		cfg.DBMaxIdleConns = cfg.DBMaxOpenConns
	}

	return cfg
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// getEnvDuration parses a Go duration ("10m", "0s"); a malformed or negative
// value is reported and the default used.
func getEnvDuration(key string, defaultValue time.Duration) time.Duration {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	d, err := time.ParseDuration(value)
	if err != nil || d < 0 {
		log.Printf("[config] ignoring %s=%q: not a duration like 10m; using %s", key, value, defaultValue)
		return defaultValue
	}
	return d
}

func getEnvInt(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if n, err := strconv.Atoi(value); err == nil && n > 0 {
			return n
		}
	}
	return defaultValue
}
