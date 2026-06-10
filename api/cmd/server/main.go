package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/labstack/echo/v4"

	"nginx-proxy-guard/internal/bootstrap"
	"nginx-proxy-guard/internal/config"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "reset-password":
			os.Exit(runResetPasswordCommand(os.Args[2:]))
		}
	}

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
	e.IPExtractor = trustedProxyIPExtractor()
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

// trustedProxyIPExtractor returns an IPExtractor that resolves the real client
// IP from the X-Forwarded-For header, trusting only the front proxy (the UI
// nginx) and the loopback address.
//
// Without this, c.RealIP() falls back to Echo's legacy behavior and trusts the
// leftmost XFF entry — fully client-controllable. That value drives login
// lockout counting, API-token IP allow-lists, and rate limiting, so a spoofed
// XFF would let an attacker bypass all three (H3).
//
// We trust the Docker bridge range (172.16.0.0/12) — the network the single
// front proxy sits on — plus loopback. We intentionally do NOT trust all
// private nets (TrustPrivateNet), so XFF entries forged by an upstream backend
// on 10.x/192.168.x are not honored. Operators running on a different compose
// network can override the trusted range via TRUSTED_PROXY_CIDR.
func trustedProxyIPExtractor() echo.IPExtractor {
	cidr := os.Getenv("TRUSTED_PROXY_CIDR")
	if cidr == "" {
		// Default Docker bridge / compose network range.
		cidr = "172.16.0.0/12"
	}

	opts := []echo.TrustOption{
		echo.TrustLoopback(true), // 127.0.0.1 (same-host proxy)
		echo.TrustLinkLocal(false),
		echo.TrustPrivateNet(false), // do not blanket-trust 10.x / 192.168.x
	}
	if _, ipNet, err := net.ParseCIDR(cidr); err == nil {
		opts = append(opts, echo.TrustIPRange(ipNet))
	} else {
		log.Printf("[Startup] Warning: invalid TRUSTED_PROXY_CIDR %q, ignoring: %v", cidr, err)
	}

	return echo.ExtractIPFromXFFHeader(opts...)
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
