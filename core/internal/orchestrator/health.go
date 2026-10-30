// Package orchestrator manages engine registration, lifecycle, and health monitoring.
package orchestrator

import (
	"context"
	"crypto/tls"
	"net/http"
	"sync"
	"time"

	"sentrix/core/internal/config"
	"sentrix/core/pkg/models"
)

// HealthState represents the operational status of an engine.
type HealthState string

const (
	StateHealthy  HealthState = "HEALTHY"
	StateDegraded HealthState = "DEGRADED"
	StateDown     HealthState = "DOWN"
	StateDisabled HealthState = "DISABLED"
	StateUnknown  HealthState = "UNKNOWN"
)

// EngineHealth contains the live diagnostic report of an engine.
type EngineHealth struct {
	Name            string        `json:"name"`
	Type            models.EngineSource `json:"type"`
	State           HealthState   `json:"state"`
	Enabled         bool          `json:"enabled"`
	Endpoint        string        `json:"endpoint"`
	LastCheck       time.Time           `json:"last_check"`
	LatencyMs       int64               `json:"latency_ms"`
	ConsecutiveFails int                `json:"consecutive_failures"`
	LastError       string        `json:"last_error,omitempty"`
}

// Engine represents the contract every security engine adapter must fulfill.
type Engine interface {
	Name() string
	Type() models.EngineSource
	Config() config.EngineEndpoint
	CheckHealth(ctx context.Context) EngineHealth
}

// HTTPEngine is a generic engine adapter probing an HTTP/HTTPS health endpoint.
type HTTPEngine struct {
	name      string
	engType   models.EngineSource
	endpoint  config.EngineEndpoint
	client    *http.Client
	mu        sync.RWMutex
	lastHealth EngineHealth
}

// NewHTTPEngine creates a new generic HTTP engine health checker.
func NewHTTPEngine(name string, engType models.EngineSource, endpoint config.EngineEndpoint) *HTTPEngine {
	timeout := endpoint.Timeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}

	// Transport configuration with skip-verify for local self-signed dev certificates (e.g., Wazuh 55000)
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	return &HTTPEngine{
		name:     name,
		engType:  engType,
		endpoint: endpoint,
		client: &http.Client{
			Timeout:   timeout,
			Transport: tr,
		},
		lastHealth: EngineHealth{
			Name:     name,
			Type:     engType,
			State:    StateUnknown,
			Enabled:  endpoint.Enabled,
			Endpoint: endpoint.URL,
		},
	}
}

func (e *HTTPEngine) Name() string {
	return e.name
}

func (e *HTTPEngine) Type() models.EngineSource {
	return e.engType
}

func (e *HTTPEngine) Config() config.EngineEndpoint {
	return e.endpoint
}

// CheckHealth probes the engine's endpoint and returns an updated EngineHealth report.
func (e *HTTPEngine) CheckHealth(ctx context.Context) EngineHealth {
	e.mu.Lock()
	defer e.mu.Unlock()

	now := time.Now()
	e.lastHealth.LastCheck = now

	if !e.endpoint.Enabled {
		e.lastHealth.State = StateDisabled
		e.lastHealth.LastError = ""
		e.lastHealth.LatencyMs = 0
		return e.lastHealth
	}

	if e.endpoint.URL == "" {
		e.lastHealth.State = StateDown
		e.lastHealth.LastError = "endpoint URL is not configured"
		return e.lastHealth
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.endpoint.URL, nil)
	if err != nil {
		e.lastHealth.State = StateDown
		e.lastHealth.ConsecutiveFails++
		e.lastHealth.LastError = err.Error()
		return e.lastHealth
	}

	// Add auth header if present
	if e.endpoint.APIKey != "" {
		req.Header.Set("X-Api-Key", e.endpoint.APIKey)
	}

	start := time.Now()
	resp, err := e.client.Do(req)
	latency := time.Since(start)
	e.lastHealth.LatencyMs = latency.Milliseconds()

	if err != nil {
		e.lastHealth.State = StateDown
		e.lastHealth.ConsecutiveFails++
		e.lastHealth.LastError = err.Error()
		return e.lastHealth
	}
	defer resp.Body.Close()

	if (resp.StatusCode >= 200 && resp.StatusCode < 400) || resp.StatusCode == http.StatusUnauthorized {
		e.lastHealth.State = StateHealthy
		e.lastHealth.ConsecutiveFails = 0
		e.lastHealth.LastError = ""
	} else {
		e.lastHealth.State = StateDegraded
		e.lastHealth.ConsecutiveFails++
		e.lastHealth.LastError = resp.Status
	}

	return e.lastHealth
}
