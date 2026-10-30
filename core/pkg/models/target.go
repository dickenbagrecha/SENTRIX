// Package models defines canonical structures for targets, scopes, and security assessments.
package models

import (
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// TargetConfig defines an explicitly authorised testing target and its safety scope.
type TargetConfig struct {
	TargetID               string   `json:"target_id"`
	Name                   string   `json:"name"`
	BaseURL                string   `json:"base_url"`
	Environment            string   `json:"environment"` // "staging", "development", "sandbox"
	AllowedHosts           []string `json:"allowed_hosts"`
	AllowedEndpoints       []string `json:"allowed_endpoints"`
	AuthHeader             string   `json:"auth_header,omitempty"`
	ScopeToken             string   `json:"scope_token"` // Cryptographic / explicit consent token
	UseSyntheticDataOnly   bool     `json:"use_synthetic_data_only"`
	MaxRequestsPerSecond   int      `json:"max_requests_per_second"`
	SafeMode               bool     `json:"safe_mode"` // If true, non-destructive payloads only
}

// DefaultStagingTarget creates a default safety-scoped target for local/staging testing.
func DefaultStagingTarget() *TargetConfig {
	return &TargetConfig{
		TargetID:             "vlookup-staging-01",
		Name:                 "V-LOOKUP Staging Environment",
		BaseURL:              "http://127.0.0.1:8080",
		Environment:          "staging",
		AllowedHosts:         []string{"127.0.0.1", "localhost", "staging.vlookup.local", "host.docker.internal"},
		AllowedEndpoints:     []string{"/api/v1/*", "/auth/*", "/documents/*"},
		UseSyntheticDataOnly: true,
		MaxRequestsPerSecond: 20,
		SafeMode:             true,
		ScopeToken:           "AUTH-SCOPE-VLOOKUP-STAGING-CONFIRMED",
	}
}

// Validate checks that the target configuration complies with all mandatory safety rules.
func (t *TargetConfig) Validate() error {
	if t.BaseURL == "" {
		return errors.New("base_url is required")
	}

	u, err := url.Parse(t.BaseURL)
	if err != nil {
		return fmt.Errorf("invalid base_url '%s': %w", t.BaseURL, err)
	}

	// Safety Rule: Restrict to non-production environments by default
	env := strings.ToLower(t.Environment)
	if env == "production" || env == "prod" {
		return errors.New("safety violation: testing production environments directly is prohibited")
	}

	if t.ScopeToken == "" {
		return errors.New("scope_token is required to prove explicit testing authorization")
	}

	// Host validation
	host := u.Hostname()
	allowed := false
	for _, h := range t.AllowedHosts {
		if strings.EqualFold(h, host) {
			allowed = true
			break
		}
	}
	if !allowed {
		return fmt.Errorf("host '%s' is not in the allowed_hosts whitelist: %v", host, t.AllowedHosts)
	}

	if !t.UseSyntheticDataOnly {
		return errors.New("safety violation: use_synthetic_data_only must be true")
	}

	if t.MaxRequestsPerSecond <= 0 || t.MaxRequestsPerSecond > 100 {
		t.MaxRequestsPerSecond = 20 // Default safe limit
	}

	return nil
}

// IsPathAllowed checks if a candidate endpoint path falls within the target's scope whitelist.
func (t *TargetConfig) IsPathAllowed(path string) bool {
	if len(t.AllowedEndpoints) == 0 {
		return true
	}
	for _, allowed := range t.AllowedEndpoints {
		if allowed == "*" {
			return true
		}
		if strings.HasSuffix(allowed, "/*") {
			prefix := strings.TrimSuffix(allowed, "/*")
			if strings.HasPrefix(path, prefix) {
				return true
			}
		} else if strings.EqualFold(allowed, path) {
			return true
		}
	}
	return false
}
