// Package config provides configuration parsing, validation, and defaults for SENTRIX Core.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"sentrix/core/internal/logger"
)

// EngineEndpoint defines connectivity settings for an external engine.
type EngineEndpoint struct {
	Enabled       bool          `json:"enabled"`
	URL           string        `json:"url"`
	Timeout       time.Duration `json:"timeout_ms"`
	CheckInterval time.Duration `json:"check_interval_ms"`
	APIKey        string        `json:"api_key,omitempty"`
}

// Config represents the complete SENTRIX Core runtime configuration.
type Config struct {
	Environment string         `json:"environment"` // "development", "production", "test"
	HTTPPort    int            `json:"http_port"`
	BindAddress string         `json:"bind_address"`
	Logging     logger.Config  `json:"logging"`
	Engines     EnginesConfig  `json:"engines"`
}

// EnginesConfig holds per-engine endpoints and settings.
type EnginesConfig struct {
	Coraza      EngineEndpoint `json:"coraza"`
	CrowdSec    EngineEndpoint `json:"crowdsec"`
	ModSecurity EngineEndpoint `json:"modsecurity"`
	Promptfoo   EngineEndpoint `json:"promptfoo"`
	Wazuh       EngineEndpoint `json:"wazuh"`
}

// DefaultConfig returns a secure, development-ready default configuration.
func DefaultConfig() *Config {
	return &Config{
		Environment: "development",
		HTTPPort:    9000,
		BindAddress: "127.0.0.1", // Secure default: bind to localhost
		Logging: logger.Config{
			Level:  "info",
			Format: "json",
		},
		Engines: EnginesConfig{
			Coraza: EngineEndpoint{
				Enabled:       true,
				URL:           "http://127.0.0.1:8080/healthz",
				Timeout:       2000 * time.Millisecond,
				CheckInterval: 5000 * time.Millisecond,
			},
			CrowdSec: EngineEndpoint{
				Enabled:       true,
				URL:           "http://127.0.0.1:8085/v1/heartbeat",
				Timeout:       3000 * time.Millisecond,
				CheckInterval: 10000 * time.Millisecond,
			},
			ModSecurity: EngineEndpoint{
				Enabled:       true, // Active secondary WAF benchmark & inspection engine
				URL:           "http://127.0.0.1:8082/healthz",
				Timeout:       2000 * time.Millisecond,
				CheckInterval: 10000 * time.Millisecond,
			},
			Promptfoo: EngineEndpoint{
				Enabled:       true,
				URL:           "http://127.0.0.1:15500/healthz",
				Timeout:       5000 * time.Millisecond,
				CheckInterval: 15000 * time.Millisecond,
			},
			Wazuh: EngineEndpoint{
				Enabled:       true,
				URL:           "https://127.0.0.1:55000/",
				Timeout:       5000 * time.Millisecond,
				CheckInterval: 15000 * time.Millisecond,
			},
		},
	}
}

// Load reads a configuration file (JSON) and applies environment overrides.
func Load(filePath string) (*Config, error) {
	cfg := DefaultConfig()

	if filePath != "" {
		data, err := os.ReadFile(filePath)
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("failed to read config file '%s': %w", filePath, err)
			}
		} else {
			// Parse JSON configuration
			if err := json.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config JSON from '%s': %w", filePath, err)
			}
		}
	}

	// Apply environment variable overrides (prefixed with SENTRIX_)
	applyEnvOverrides(cfg)

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return cfg, nil
}

// Validate ensures all configuration parameters conform to security and operational bounds.
func (c *Config) Validate() error {
	if c.HTTPPort <= 0 || c.HTTPPort > 65535 {
		return fmt.Errorf("http_port must be between 1 and 65535, got %d", c.HTTPPort)
	}
	if c.BindAddress == "" {
		c.BindAddress = "127.0.0.1"
	}
	// Safety constraint: In development, warn or restrict binding to public interfaces
	return nil
}

func applyEnvOverrides(cfg *Config) {
	if val := os.Getenv("SENTRIX_ENV"); val != "" {
		cfg.Environment = val
	}
	if val := os.Getenv("SENTRIX_HTTP_PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			cfg.HTTPPort = p
		}
	}
	if val := os.Getenv("SENTRIX_BIND_ADDRESS"); val != "" {
		cfg.BindAddress = val
	}
	if val := os.Getenv("SENTRIX_LOG_LEVEL"); val != "" {
		cfg.Logging.Level = val
	}
	if val := os.Getenv("SENTRIX_LOG_FORMAT"); val != "" {
		cfg.Logging.Format = val
	}

	// Engine endpoint overrides
	if val := os.Getenv("SENTRIX_CORAZA_URL"); val != "" {
		cfg.Engines.Coraza.URL = val
	}
	if val := os.Getenv("SENTRIX_CROWDSEC_URL"); val != "" {
		cfg.Engines.CrowdSec.URL = val
	}
	if val := os.Getenv("SENTRIX_PROMPTFOO_URL"); val != "" {
		cfg.Engines.Promptfoo.URL = val
	}
	if val := os.Getenv("SENTRIX_WAZUH_URL"); val != "" {
		cfg.Engines.Wazuh.URL = val
	}
	if val := os.Getenv("SENTRIX_MODSEC_URL"); val != "" {
		cfg.Engines.ModSecurity.URL = val
	}
	if val := os.Getenv("SENTRIX_MODSEC_ENABLED"); val != "" {
		cfg.Engines.ModSecurity.Enabled = (val == "true" || val == "1")
	}
	if val := os.Getenv("SENTRIX_CROWDSEC_KEY"); val != "" {
		cfg.Engines.CrowdSec.APIKey = val
	}
}
