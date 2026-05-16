package bootstrap

import (
	"log"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/pkg/cache"
)

// InitDB initializes the database connection pool and runs migrations.
// Pool sizing is applied BEFORE RunMigrations so the migration's background
// goroutines (each acquiring a connection) start under the operator's final
// pool limits instead of the New() defaults. Otherwise an operator who set
// NPG_DB_MAX_OPEN smaller than 80 would briefly run with the larger default.
func InitDB(cfg *config.Config) (*database.DB, error) {
	db, err := database.New(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	db.SetPool(cfg.DBMaxOpenConns, cfg.DBMaxIdleConns)
	log.Printf("Connected to database (pool: max_open=%d max_idle=%d)", cfg.DBMaxOpenConns, cfg.DBMaxIdleConns)

	if err := db.RunMigrations(); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

// InitCache attempts to initialize the Valkey/Redis cache client.
// Returns nil on failure — callers must tolerate a nil cache (graceful degradation).
func InitCache(cfg *config.Config) *cache.RedisClient {
	redisCache, err := cache.NewRedisClient(cfg.RedisURL)
	if err != nil {
		log.Printf("Warning: Failed to initialize Redis cache: %v", err)
		return nil
	}
	log.Println("Redis cache client initialized")
	return redisCache
}
