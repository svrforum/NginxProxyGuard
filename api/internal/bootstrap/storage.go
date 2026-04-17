package bootstrap

import (
	"log"

	"nginx-proxy-guard/internal/config"
	"nginx-proxy-guard/internal/database"
	"nginx-proxy-guard/pkg/cache"
)

// InitDB initializes the database connection pool and runs migrations.
func InitDB(cfg *config.Config) (*database.DB, error) {
	db, err := database.New(cfg.DatabaseURL)
	if err != nil {
		return nil, err
	}
	log.Println("Connected to database")

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
