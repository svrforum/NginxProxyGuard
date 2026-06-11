package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	shutdownDone := make(chan struct{})
	go handleShutdown(cancel, c, e, shutdownDone)

	port := cfg.Port
	if port == "" {
		port = "8080"
	}
	log.Printf("Starting server on port %s", port)
	if err := e.Start(":" + port); err != nil && err != http.ErrServerClosed {
		log.Fatalf("Server error: %v", err)
	}

	// e.Start returns ErrServerClosed as soon as Shutdown() is invoked, while
	// the drain is still in progress. Wait for handleShutdown to finish before
	// the deferred c.Close() tears down DB/cache underneath in-flight requests
	// and stopping background services.
	<-shutdownDone
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

// handleShutdown blocks on SIGINT/SIGTERM and triggers a graceful shutdown:
//
//  1. cancel() — root-ctx background loops (log collectors, stats, …) begin
//     winding down concurrently with the HTTP drain.
//  2. e.Shutdown — stop accepting new connections, then drain in-flight
//     requests (bounded). A request holding globalNginxMutex mid
//     write→test→reload gets to finish instead of being severed, which kept
//     leaving DB-committed changes half-applied to nginx.
//  3. c.StopAll — synchronous stop of background services and schedulers,
//     after no new work can arrive.
//  4. main's deferred c.Close() releases DB/cache last (DB.Close additionally
//     waits up to 5s for tracked migration goroutines).
//
// Deliberately NOT drained: detached goroutines on context.Background() —
// ACME issuance/renewal (service/certificate*.go), the cert-ready config
// regen callback (bootstrap/services.go) and ban fan-outs. Tracking them
// would require invasive plumbing; interruption is tolerated by design
// (startup recovers stranded cert states, SyncAllConfigs reconciles configs).
//
// Note the drain budget must stay under Docker's stop_grace_period (default
// 10s) or dockerd SIGKILLs us before StopAll/Close run.
func handleShutdown(cancel context.CancelFunc, c *bootstrap.Container, e *echo.Echo, done chan<- struct{}) {
	defer close(done)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("Shutting down...")
	cancel()

	drainCtx, cancelDrain := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancelDrain()
	if err := e.Shutdown(drainCtx); err != nil {
		log.Printf("Shutdown: HTTP drain incomplete (%v), closing remaining connections", err)
		_ = e.Close()
	}

	c.StopAll()
}
