// Package api exposes REST endpoints for SENTRIX Core health, metrics, adversarial auditing, and remediation tracking.
package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"sentrix/core/internal/auditor"
	"sentrix/core/internal/config"
	"sentrix/core/internal/orchestrator"
	"sentrix/core/internal/remediation"
	"sentrix/core/internal/reporter"
	"sentrix/core/pkg/models"
)

// Server coordinates the HTTP server lifecycle and route registration.
type Server struct {
	cfg          *config.Config
	logger       *slog.Logger
	orchestrator *orchestrator.Orchestrator
	auditor      *auditor.Auditor
	tracker      *remediation.Tracker
	httpServer   *http.Server
	startTime    time.Time
}

// SystemStatus represents the overall platform health response.
type SystemStatus struct {
	Status      string                             `json:"status"` // "UP", "DEGRADED", "DOWN"
	Version     string                             `json:"version"`
	Environment string                             `json:"environment"`
	UptimeSec   int64                              `json:"uptime_sec"`
	Timestamp   time.Time                          `json:"timestamp"`
	Engines     map[string]orchestrator.EngineHealth `json:"engines"`
}

// TransitionRequest defines the payload for transitioning a finding's remediation lifecycle state.
type TransitionRequest struct {
	NewState models.RemediationState `json:"new_state"`
	Actor    string                  `json:"actor"`
	Comment  string                  `json:"comment"`
}

// NewServer initializes the HTTP API server with all subsystems wired together.
func NewServer(
	cfg *config.Config,
	logger *slog.Logger,
	orch *orchestrator.Orchestrator,
	auditor *auditor.Auditor,
	tracker *remediation.Tracker,
) *Server {
	s := &Server{
		cfg:          cfg,
		logger:       logger,
		orchestrator: orch,
		auditor:      auditor,
		tracker:      tracker,
		startTime:    time.Now(),
	}

	mux := http.NewServeMux()
	
	// System & Health Endpoints
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /api/v1/health", s.handleSystemHealth)
	mux.HandleFunc("GET /api/v1/engines", s.handleEnginesStatus)
	mux.HandleFunc("POST /api/v1/events/normalize", s.handleNormalizeEvent)

	// Auditing & Adversarial Test Endpoints
	mux.HandleFunc("POST /api/v1/audits/run", s.handleRunAudit)

	// Remediation Tracking & Developer Reports Endpoints
	mux.HandleFunc("GET /api/v1/findings", s.handleListFindings)
	mux.HandleFunc("GET /api/v1/findings/", s.handleGetFindingOrReport) // handles /findings/{id} and /findings/{id}/report
	mux.HandleFunc("POST /api/v1/findings/", s.handleFindingActions)    // handles /findings/{id}/transition
	mux.HandleFunc("POST /api/v1/remediation/retest/", s.handleRetestFinding)

	addr := fmt.Sprintf("%s:%d", cfg.BindAddress, cfg.HTTPPort)
	s.httpServer = &http.Server{
		Addr:         addr,
		Handler:      s.loggingMiddleware(mux),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return s
}

// Start begins listening on the configured address.
func (s *Server) Start() error {
	s.logger.Info("starting SENTRIX Core API server",
		"address", s.httpServer.Addr,
		"environment", s.cfg.Environment,
	)

	ln, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return fmt.Errorf("failed to bind address '%s': %w", s.httpServer.Addr, err)
	}

	return s.httpServer.Serve(ln)
}

// Shutdown gracefully terminates the HTTP server with a context timeout.
func (s *Server) Shutdown(ctx context.Context) error {
	s.logger.Info("shutting down HTTP API server")
	return s.httpServer.Shutdown(ctx)
}

// Handler returns the root HTTP handler for testing and external embedding.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// handleHealthz responds with 200 OK if Core itself is running (Kubernetes liveness probe).
func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status": "UP",
		"time":   time.Now().UTC().Format(time.RFC3339),
	})
}

// handleSystemHealth aggregates health across all engines and returns composite readiness status.
func (s *Server) handleSystemHealth(w http.ResponseWriter, r *http.Request) {
	engineStatus := s.orchestrator.GetStatus(r.Context())

	overall := "UP"
	for _, h := range engineStatus {
		if h.Enabled && h.State == orchestrator.StateDown {
			overall = "DEGRADED"
			break
		}
	}

	status := SystemStatus{
		Status:      overall,
		Version:     "0.1.0-alpha",
		Environment: s.cfg.Environment,
		UptimeSec:   int64(time.Since(s.startTime).Seconds()),
		Timestamp:   time.Now().UTC(),
		Engines:     engineStatus,
	}

	w.Header().Set("Content-Type", "application/json")
	if overall == "UP" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	_ = json.NewEncoder(w).Encode(status)
}

// handleEnginesStatus lists the detailed state of each engine.
func (s *Server) handleEnginesStatus(w http.ResponseWriter, r *http.Request) {
	engineStatus := s.orchestrator.GetStatus(r.Context())
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(engineStatus)
}

// handleNormalizeEvent receives a candidate event, validates it, and echoes normalized SCSE format.
func (s *Server) handleNormalizeEvent(w http.ResponseWriter, r *http.Request) {
	var event models.SCSEEvent
	if err := json.NewDecoder(r.Body).Decode(&event); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid JSON payload: "+err.Error())
		return
	}

	if err := event.Validate(); err != nil {
		s.respondError(w, http.StatusUnprocessableEntity, "SCSE validation failed: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"valid": true,
		"event": event,
	})
}

// handleRunAudit triggers a controlled adversarial test run across the 12 attack categories.
func (s *Server) handleRunAudit(w http.ResponseWriter, r *http.Request) {
	var target models.TargetConfig
	if err := json.NewDecoder(r.Body).Decode(&target); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid target configuration JSON: "+err.Error())
		return
	}

	// Validate target scope authorization
	if err := target.Validate(); err != nil {
		s.respondError(w, http.StatusForbidden, "target authorization rejected: "+err.Error())
		return
	}

	scenarios := s.auditor.BuildDefaultScenarios(&target)
	var generatedFindings []*models.VulnerabilityFinding

	for _, sc := range scenarios {
		finding, err := s.auditor.ExecuteScenario(r.Context(), &target, sc)
		if err != nil {
			s.logger.Warn("scenario execution anomaly", "scenario_id", sc.ID, "error", err)
			continue
		}
		if finding != nil {
			s.tracker.Add(finding)
			generatedFindings = append(generatedFindings, finding)
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"status":          "COMPLETED",
		"target_id":       target.TargetID,
		"scenarios_run":   len(scenarios),
		"findings_count":  len(generatedFindings),
		"findings":        generatedFindings,
	})
}

// handleListFindings returns findings, optionally filtered by ?state=
func (s *Server) handleListFindings(w http.ResponseWriter, r *http.Request) {
	var filterState *models.RemediationState
	if stateStr := r.URL.Query().Get("state"); stateStr != "" {
		st := models.RemediationState(stateStr)
		filterState = &st
	}

	findings := s.tracker.List(filterState)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"count":    len(findings),
		"findings": findings,
	})
}

// handleGetFindingOrReport serves GET /api/v1/findings/{id} and GET /api/v1/findings/{id}/report
func (s *Server) handleGetFindingOrReport(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/findings/")
	parts := strings.Split(path, "/")
	findingID := parts[0]

	finding, exists := s.tracker.Get(findingID)
	if !exists {
		s.respondError(w, http.StatusNotFound, "vulnerability finding not found")
		return
	}

	// If asking for /report, render actionable Markdown
	if len(parts) > 1 && parts[1] == "report" {
		md, err := reporter.GenerateMarkdown(finding)
		if err != nil {
			s.respondError(w, http.StatusInternalServerError, "failed to generate report: "+err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(md))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(finding)
}

// handleFindingActions handles POST /api/v1/findings/{id}/transition
func (s *Server) handleFindingActions(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/findings/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "transition" {
		s.respondError(w, http.StatusNotFound, "endpoint not found")
		return
	}
	findingID := parts[0]

	var req TransitionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		s.respondError(w, http.StatusBadRequest, "invalid transition request payload: "+err.Error())
		return
	}

	if err := s.tracker.Transition(findingID, req.NewState, req.Actor, req.Comment); err != nil {
		s.respondError(w, http.StatusConflict, err.Error())
		return
	}

	updatedFinding, _ := s.tracker.Get(findingID)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(updatedFinding)
}

// handleRetestFinding handles POST /api/v1/remediation/retest/{id}
func (s *Server) handleRetestFinding(w http.ResponseWriter, r *http.Request) {
	findingID := strings.TrimPrefix(r.URL.Path, "/api/v1/remediation/retest/")
	finding, exists := s.tracker.Get(findingID)
	if !exists {
		s.respondError(w, http.StatusNotFound, "finding not found")
		return
	}

	target := models.DefaultStagingTarget()
	if r.Body != nil {
		var customTarget models.TargetConfig
		if err := json.NewDecoder(r.Body).Decode(&customTarget); err == nil && customTarget.BaseURL != "" {
			target = &customTarget
		}
	}

	verified, err := s.tracker.ExecuteRegressionTest(r.Context(), findingID, target, "developer-retest-request")
	if err != nil {
		s.respondError(w, http.StatusInternalServerError, "regression test failed: "+err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"finding_id": findingID,
		"verified":   verified,
		"new_state":  finding.State,
	})
}

func (s *Server) respondError(w http.ResponseWriter, statusCode int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":  message,
		"status": statusCode,
	})
}

func (s *Server) loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		next.ServeHTTP(w, r)
		s.logger.Debug("HTTP request served",
			"method", r.Method,
			"path", r.URL.Path,
			"remote", r.RemoteAddr,
			"duration", time.Since(start).String(),
		)
	})
}
