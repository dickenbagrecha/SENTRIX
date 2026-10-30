// Package main is the primary entry point for the SENTRIX Core orchestration daemon.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentrix/core/internal/api"
	"sentrix/core/internal/auditor"
	"sentrix/core/internal/config"
	"sentrix/core/internal/logger"
	"sentrix/core/internal/orchestrator"
	"sentrix/core/internal/remediation"
)

var (
	version   = "0.1.0-alpha"
	commit    = "dev"
	buildTime = "unspecified"
)

func main() {
	configPath := flag.String("config", "", "Path to configuration file (JSON)")
	showVersion := flag.Bool("version", false, "Print version information and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("SENTRIX Core v%s (commit: %s, built: %s)\n", version, commit, buildTime)
		os.Exit(0)
	}

	// 1. Load Configuration
	cfg, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FATAL: Configuration error: %v\n", err)
		os.Exit(1)
	}

	// 2. Initialize Structured Logger
	log := logger.New(cfg.Logging, os.Stdout)
	log.Info("starting SENTRIX Core orchestration daemon",
		"version", version,
		"environment", cfg.Environment,
		"http_port", cfg.HTTPPort,
		"bind_address", cfg.BindAddress,
	)

	// 3. Initialize Orchestrator & Register Engines
	orch := orchestrator.New(cfg, log)
	orch.RegisterDefaultEngines()

	// 4. Initialize Auditor & Remediation Tracker
	auditRunner := auditor.New(log)
	tracker := remediation.NewTracker(auditRunner)

	// 5. Start Health Monitoring Supervisor
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	orch.Start(ctx)

	// 6. Initialize & Start API Server
	srv := api.NewServer(cfg, log, orch, auditRunner, tracker)
	go func() {
		if err := srv.Start(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("API server terminated unexpectedly", "error", err)
			os.Exit(1)
		}
	}()

	// 6. Graceful Shutdown on System Signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)

	sig := <-sigChan
	log.Info("shutdown signal received", "signal", sig.String())

	// Shutdown with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	// Stop accepting new HTTP requests
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error("HTTP server graceful shutdown error", "error", err)
	}

	// Stop health monitoring background goroutines
	orch.Stop()

	log.Info("SENTRIX Core terminated gracefully")
}
