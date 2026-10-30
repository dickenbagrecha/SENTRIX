package orchestrator

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"sentrix/core/internal/config"
	"sentrix/core/pkg/models"
)

// Orchestrator coordinates the lifecycle and health surveillance of all registered engines.
type Orchestrator struct {
	logger  *slog.Logger
	cfg     *config.Config
	engines map[string]Engine
	mu      sync.RWMutex
	cancel  context.CancelFunc
	wg      sync.WaitGroup
}

// New creates and initializes an Orchestrator instance.
func New(cfg *config.Config, logger *slog.Logger) *Orchestrator {
	return &Orchestrator{
		logger:  logger,
		cfg:     cfg,
		engines: make(map[string]Engine),
	}
}

// RegisterEngine adds an engine to the orchestrator registry.
func (o *Orchestrator) RegisterEngine(engine Engine) {
	o.mu.Lock()
	defer o.mu.Unlock()

	o.engines[engine.Name()] = engine
	o.logger.Info("registered security engine",
		"engine", engine.Name(),
		"type", engine.Type(),
		"enabled", engine.Config().Enabled,
		"endpoint", engine.Config().URL,
	)
}

// RegisterDefaultEngines registers all five standard SENTRIX engines from configuration.
func (o *Orchestrator) RegisterDefaultEngines() {
	o.RegisterEngine(NewHTTPEngine("coraza", models.EngineCoraza, o.cfg.Engines.Coraza))
	o.RegisterEngine(NewHTTPEngine("crowdsec", models.EngineCrowdSec, o.cfg.Engines.CrowdSec))
	o.RegisterEngine(NewHTTPEngine("modsecurity", models.EngineModSecurity, o.cfg.Engines.ModSecurity))
	o.RegisterEngine(NewHTTPEngine("promptfoo", models.EnginePromptfoo, o.cfg.Engines.Promptfoo))
	o.RegisterEngine(NewHTTPEngine("wazuh", models.EngineWazuh, o.cfg.Engines.Wazuh))
}

// Start begins periodic background health checking for all registered engines.
func (o *Orchestrator) Start(ctx context.Context) {
	o.mu.Lock()
	checkCtx, cancel := context.WithCancel(ctx)
	o.cancel = cancel
	o.mu.Unlock()

	o.logger.Info("starting engine health supervisor")

	// Perform initial synchronous health check
	o.CheckAll(checkCtx)

	// Launch periodic health check loops per engine
	o.mu.RLock()
	defer o.mu.RUnlock()

	for _, eng := range o.engines {
		if !eng.Config().Enabled {
			continue
		}

		interval := eng.Config().CheckInterval
		if interval <= 0 {
			interval = 10 * time.Second
		}

		o.wg.Add(1)
		go func(e Engine, d time.Duration) {
			defer o.wg.Done()
			ticker := time.NewTicker(d)
			defer ticker.Stop()

			for {
				select {
				case <-checkCtx.Done():
					return
				case <-ticker.C:
					h := e.CheckHealth(checkCtx)
					if h.State != StateHealthy && h.State != StateDisabled {
						o.logger.Warn("engine health degraded",
							"engine", h.Name,
							"state", h.State,
							"latency", fmt.Sprintf("%dms", h.LatencyMs),
							"failures", h.ConsecutiveFails,
							"error", h.LastError,
						)
					} else if h.State == StateHealthy {
						o.logger.Debug("engine healthy",
							"engine", h.Name,
							"latency", fmt.Sprintf("%dms", h.LatencyMs),
						)
					}
				}
			}
		}(eng, interval)
	}
}

// Stop gracefully terminates the health checking routines.
func (o *Orchestrator) Stop() {
	o.mu.Lock()
	if o.cancel != nil {
		o.cancel()
	}
	o.mu.Unlock()

	o.wg.Wait()
	o.logger.Info("engine health supervisor stopped")
}

// CheckAll manually triggers health checks across all registered engines.
func (o *Orchestrator) CheckAll(ctx context.Context) map[string]EngineHealth {
	o.mu.RLock()
	engines := make([]Engine, 0, len(o.engines))
	for _, e := range o.engines {
		engines = append(engines, e)
	}
	o.mu.RUnlock()

	results := make(map[string]EngineHealth)
	var wg sync.WaitGroup
	var resultsMu sync.Mutex

	for _, eng := range engines {
		wg.Add(1)
		go func(e Engine) {
			defer wg.Done()
			h := e.CheckHealth(ctx)
			resultsMu.Lock()
			results[e.Name()] = h
			resultsMu.Unlock()
		}(eng)
	}

	wg.Wait()
	return results
}

// GetStatus returns the most recent health status of all registered engines.
func (o *Orchestrator) GetStatus(ctx context.Context) map[string]EngineHealth {
	return o.CheckAll(ctx)
}
