package tests

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentrix/core/internal/config"
	"sentrix/core/internal/orchestrator"
	"sentrix/core/internal/reporter"
	"sentrix/core/pkg/models"
)

func TestEvidenceRedaction(t *testing.T) {
	// 1. Test JWT redaction
	sampleJWT := "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	redacted := models.RedactSensitiveData(sampleJWT)
	if strings.Contains(redacted, "eyJhbGci") {
		t.Errorf("expected JWT to be redacted, got: %s", redacted)
	}
	if !strings.Contains(redacted, "[REDACTED_TOKEN]") && !strings.Contains(redacted, "[REDACTED_JWT]") {
		t.Errorf("expected token redaction placeholder, got: %s", redacted)
	}

	// 2. Test Key-Value password/secret in JSON and text
	sampleJSON := `{"status": 500, "error": "connection failed", "db_password": "super_secret_db_pass_123!", "api_key": "AKIAIOSFODNN7EXAMPLE"}`
	redactedJSON := models.RedactSensitiveData(sampleJSON)
	if strings.Contains(redactedJSON, "super_secret_db_pass_123!") {
		t.Errorf("expected db_password to be redacted, got: %s", redactedJSON)
	}
	if strings.Contains(redactedJSON, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("expected api_key to be redacted, got: %s", redactedJSON)
	}

	// 3. Test Session Cookie redaction
	sampleCookie := "Cookie: sessionid=secret_session_xyz789; token=secret_auth_token_abc"
	redactedCookie := models.RedactSensitiveData(sampleCookie)
	if strings.Contains(redactedCookie, "secret_session_xyz789") || strings.Contains(redactedCookie, "secret_auth_token_abc") {
		t.Errorf("expected session cookies to be redacted, got: %s", redactedCookie)
	}

	// 4. Test DB URI redaction
	sampleDB := "postgres://sentrix_admin:mySuperSecretPostgresPass123@db.internal:5432/sentrix_prod"
	redactedDB := models.RedactSensitiveData(sampleDB)
	if strings.Contains(redactedDB, "mySuperSecretPostgresPass123") {
		t.Errorf("expected DB credentials to be redacted, got: %s", redactedDB)
	}

	// 5. Test Finding Sanitization and Report Generation
	finding := &models.VulnerabilityFinding{
		FindingID:        "VULN-REDACT-001",
		Category:         models.AttackDataExfiltration,
		Title:            "Verbose Error Stack Trace",
		Description:      "Database password leaked in trace",
		AffectedEndpoint: "GET /api/v1/debug",
		TechnicalEvidence: models.TechnicalEvidence{
			RequestMethod:      "GET",
			RequestURL:         "http://staging.vlookup.local/api/v1/debug",
			RequestBody:        `{"auth_token": "secret_token_val_99"}`,
			ResponseBodySample: `Internal Error: DB_PASSWORD=unredacted_raw_secret_here in postgresql.conf`,
		},
		ReproductionSteps: "curl -X GET 'http://staging.vlookup.local/api/v1/debug' -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.xyz' -H 'Cookie: sessionid=secret_session_abc'",
		DetectedAt:        time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}

	finding.Sanitize()

	if strings.Contains(finding.TechnicalEvidence.ResponseBodySample, "unredacted_raw_secret_here") {
		t.Errorf("expected ResponseBodySample to be sanitized, got: %s", finding.TechnicalEvidence.ResponseBodySample)
	}
	if strings.Contains(finding.TechnicalEvidence.RequestBody, "secret_token_val_99") {
		t.Errorf("expected RequestBody to be sanitized, got: %s", finding.TechnicalEvidence.RequestBody)
	}
	if strings.Contains(finding.ReproductionSteps, "secret_session_abc") {
		t.Errorf("expected ReproductionSteps cookie to be sanitized, got: %s", finding.ReproductionSteps)
	}

	// Ensure Markdown report contains zero leaked secrets
	md, err := reporter.GenerateMarkdown(finding)
	if err != nil {
		t.Fatalf("failed to generate markdown report: %v", err)
	}
	if strings.Contains(md, "unredacted_raw_secret_here") || strings.Contains(md, "secret_token_val_99") || strings.Contains(md, "secret_session_abc") {
		t.Errorf("markdown report leaked sensitive test credentials:\n%s", md)
	}
}

func TestTargetSecurityScopeAndPolicies(t *testing.T) {
	// 1. Valid staging configuration passes
	target := models.DefaultStagingTarget()
	if err := target.Validate(); err != nil {
		t.Fatalf("expected valid default staging target, got error: %v", err)
	}

	// 2. Production target must be explicitly rejected
	prodTarget := *target
	prodTarget.Environment = "production"
	if err := prodTarget.Validate(); err == nil {
		t.Errorf("expected validation failure for production environment, got nil")
	}

	prodTarget2 := *target
	prodTarget2.Environment = "PROD"
	if err := prodTarget2.Validate(); err == nil {
		t.Errorf("expected validation failure for PROD environment, got nil")
	}

	// 3. Target without ScopeToken must be rejected
	noScopeTarget := *target
	noScopeTarget.ScopeToken = ""
	if err := noScopeTarget.Validate(); err == nil {
		t.Errorf("expected validation failure for missing scope token, got nil")
	}

	// 4. Non-synthetic data target must be rejected
	liveDataTarget := *target
	liveDataTarget.UseSyntheticDataOnly = false
	if err := liveDataTarget.Validate(); err == nil {
		t.Errorf("expected validation failure when UseSyntheticDataOnly=false, got nil")
	}

	// 5. Host outside allowed_hosts must be rejected
	externalTarget := *target
	externalTarget.BaseURL = "https://unauthorized-production-target.com"
	if err := externalTarget.Validate(); err == nil {
		t.Errorf("expected validation failure for unauthorized external host, got nil")
	}

	// 6. Endpoint scope checks
	if !target.IsPathAllowed("/api/v1/documents/doc-123") {
		t.Errorf("expected /api/v1/documents/* path to be allowed")
	}
	if !target.IsPathAllowed("/auth/login") {
		t.Errorf("expected /auth/* path to be allowed")
	}
	if target.IsPathAllowed("/production/admin/drop-db") {
		t.Errorf("expected out-of-scope path to be rejected")
	}
}

func TestEngineHealthFailureIsolation(t *testing.T) {
	// Create mock HTTP server for healthy engine
	healthyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status": "HEALTHY"}`))
	}))
	defer healthyServer.Close()

	// Engine 1: Healthy
	engHealthy := orchestrator.NewHTTPEngine("HealthyEngine", models.EngineCoraza, config.EngineEndpoint{
		Enabled: true,
		URL:     healthyServer.URL,
		Timeout: 2 * time.Second,
	})

	// Engine 2: Down (non-existent port / connection refused)
	engDown := orchestrator.NewHTTPEngine("DownEngine", models.EngineCrowdSec, config.EngineEndpoint{
		Enabled: true,
		URL:     "http://127.0.0.1:59999/unreachable",
		Timeout: 500 * time.Millisecond,
	})

	// Engine 3: Degraded (returns 503)
	degradedServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"status": "SERVICE_UNAVAILABLE"}`))
	}))
	defer degradedServer.Close()

	engDegraded := orchestrator.NewHTTPEngine("DegradedEngine", models.EngineWazuh, config.EngineEndpoint{
		Enabled: true,
		URL:     degradedServer.URL,
		Timeout: 2 * time.Second,
	})

	ctx := context.Background()

	// Check healthy engine
	h1 := engHealthy.CheckHealth(ctx)
	if h1.State != orchestrator.StateHealthy {
		t.Errorf("expected HealthyEngine to be HEALTHY, got: %s", h1.State)
	}

	// Check down engine
	h2 := engDown.CheckHealth(ctx)
	if h2.State != orchestrator.StateDown {
		t.Errorf("expected DownEngine to be DOWN, got: %s (must not be falsely healthy)", h2.State)
	}
	if h2.LastError == "" {
		t.Errorf("expected DownEngine to record connection error details")
	}

	// Check degraded engine
	h3 := engDegraded.CheckHealth(ctx)
	if h3.State != orchestrator.StateDegraded {
		t.Errorf("expected DegradedEngine to be DEGRADED, got: %s", h3.State)
	}

	// Verify Isolation: Re-checking HealthyEngine is completely unaffected by down/degraded peers
	h1Again := engHealthy.CheckHealth(ctx)
	if h1Again.State != orchestrator.StateHealthy {
		t.Errorf("expected HealthyEngine to remain HEALTHY despite peers failing, got: %s", h1Again.State)
	}
}
