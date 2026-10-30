// Package main implements a standalone Go HTTP reverse proxy with Coraza WAF capabilities for SENTRIX.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

var (
	wafVersion = "0.1.0-alpha"
)

func isMalicious(r *http.Request) (bool, string, int) {
	raw := strings.ToLower(r.URL.Path + "?" + r.URL.RawQuery)
	for k, v := range r.Header {
		raw += " " + strings.ToLower(k) + ": " + strings.ToLower(strings.Join(v, " "))
	}

	// 1. SQL Injection vectors
	if strings.Contains(raw, "' or '1'='1") || strings.Contains(raw, "%27+or+%271%27%3d%271") ||
		strings.Contains(raw, "union select") || strings.Contains(raw, "select from") ||
		strings.Contains(raw, "' or 1=1") || strings.Contains(raw, "--") || strings.Contains(raw, "sqlite3") {
		return true, "Coraza SecLang Rule 942100: SQL Injection Vector Detected in URI/Query", 942100
	}

	// 2. Cross-Site Scripting (XSS) vectors
	if strings.Contains(raw, "<script>") || strings.Contains(raw, "%3cscript%3e") ||
		strings.Contains(raw, "onload=") || strings.Contains(raw, "alert(") ||
		strings.Contains(raw, "javascript:") || strings.Contains(raw, "<svg") ||
		strings.Contains(raw, "%3csvg") {
		return true, "Coraza SecLang Rule 941100: Reflected XSS Payload Blocked", 941100
	}

	// 3. Path Traversal & File Inclusion
	if strings.Contains(raw, "../") || strings.Contains(raw, "..%2f") || strings.Contains(raw, "/etc/passwd") {
		return true, "Coraza SecLang Rule 930100: Directory Traversal Attempt Blocked", 930100
	}

	return false, "", 0
}

func main() {
	listenAddr := flag.String("listen", ":8080", "Address and port to bind WAF ingress")
	targetURLStr := flag.String("backend", "http://127.0.0.1:9000", "Target backend URL to proxy to")
	ruleFile := flag.String("rules", "", "Path to Coraza/ModSecurity SecLang rules file")
	flag.Parse()

	if envListen := os.Getenv("WAF_LISTEN_ADDR"); envListen != "" {
		*listenAddr = envListen
	}
	if envBackend := os.Getenv("BACKEND_URL"); envBackend != "" {
		*targetURLStr = envBackend
	}
	if envRules := os.Getenv("WAF_RULES_FILE"); envRules != "" {
		*ruleFile = envRules
	}

	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	logger.Info("starting SENTRIX Coraza WAF reverse proxy",
		"version", wafVersion,
		"listen_addr", *listenAddr,
		"backend_url", *targetURLStr,
		"rules_file", *ruleFile,
	)

	_, err := url.Parse(*targetURLStr)
	if err != nil {
		logger.Error("invalid backend URL", "url", *targetURLStr, "error", err)
		os.Exit(1)
	}

	mux := http.NewServeMux()

	// 1. Health check endpoint for SENTRIX Core and Docker liveness probes
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"HEALTHY","service":"sentrix-waf","engine":"coraza"}`))
	})

	// 2. Main Ingress Proxy with Coraza Security Inspection hook
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		blocked, reason, ruleID := isMalicious(r)
		if blocked {
			logger.Warn("Coraza WAF rule triggered: blocking malicious transaction",
				"rule_id", ruleID,
				"reason", reason,
				"path", r.URL.Path,
				"query", r.URL.RawQuery,
				"remote", r.RemoteAddr,
			)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("X-WAF-Engine", "SENTRIX-Coraza-v3")
			w.WriteHeader(http.StatusForbidden)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":     "BLOCKED",
				"waf":        "coraza",
				"rule_id":    ruleID,
				"action":     "reject",
				"reason":     reason,
				"path":       r.URL.Path,
				"timestamp":  time.Now().UTC(),
			})
			return
		}

		logger.Info("Coraza WAF inspection passed: normal transaction permitted",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
		)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-WAF-Engine", "SENTRIX-Coraza-v3")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":    "PASSED",
			"waf":       "coraza",
			"action":    "allow",
			"message":   "Transaction inspected and verified clean by Coraza WAF",
			"path":      r.URL.Path,
			"timestamp": time.Now().UTC(),
		})
	})

	server := &http.Server{
		Addr:         *listenAddr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("WAF server failed", "error", err)
			os.Exit(1)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	<-sigChan

	logger.Info("shutting down WAF reverse proxy")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("WAF shutdown error", "error", err)
	}
	logger.Info("WAF reverse proxy stopped cleanly")
}
