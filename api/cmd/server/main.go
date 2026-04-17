package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/bootstrap"
	"nginx-proxy-guard/internal/config"
)

func main() {
	cfg := config.Load()

	c, err := bootstrap.NewContainer(cfg)
	if err != nil {
		log.Fatalf("Container init failed: %v", err)
	}
	defer c.Close()

	ctx, cancel := context.WithCancel(context.Background())
	if err := c.Startup(ctx); err != nil {
		log.Fatalf("Startup failed: %v", err)
	}

	e := echo.New()
	bootstrap.RegisterMiddleware(e, cfg)
	bootstrap.RegisterRoutes(e, c)

	c.StartSchedulers(ctx)

	go handleShutdown(cancel, c, e)

	port := cfg.Port
	if port == "" {
		port = "8080"
	}
	log.Printf("Starting server on port %s", port)
	if err := e.Start(":" + port); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}
}

// handleShutdown blocks on SIGINT/SIGTERM and triggers a graceful shutdown
// of background services, schedulers, and the Echo server.
func handleShutdown(cancel context.CancelFunc, c *bootstrap.Container, e *echo.Echo) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	cancel()
	c.StopAll()
	_ = e.Close()
}
