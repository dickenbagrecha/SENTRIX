package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"sentrix/core/internal/api"
	"sentrix/core/internal/auditor"
	"sentrix/core/internal/config"
	"sentrix/core/internal/logger"
	"sentrix/core/internal/orchestrator"
	"sentrix/core/internal/remediation"
	"sentrix/core/internal/reporter"
	"sentrix/core/pkg/models"
)

func TestSCSEValidation(t *testing.T) {
	validEvent := models.SCSEEvent{
		EventID:     "123e4567-e89b-12d3-a456-426614174000",
		Timestamp:   time.Now().UTC(),
		Engine:      models.EngineCoraza,
		Severity:    models.SeverityHigh,
		Category:    models.CategoryWebAttack,
		ActionTaken: models.ActionBlocked,
		Source: models.EndpointDetails{
			IP:   "192.168.1.100",
			Port: 54321,
		},
		Target: models.EndpointDetails{
			URL: "/api/login",
		},
	}

	if err := validEvent.Validate(); err != nil {
		t.Fatalf("expected valid event to pass validation, got: %v", err)
	}

	// Test invalid UUID
	invalidEvent := validEvent
	invalidEvent.EventID = "not-a-uuid"
	if err := invalidEvent.Validate(); err == nil {
		t.Errorf("expected validation error for invalid UUID, got nil")
	}

	// Test invalid Severity
	invalidSeverity := validEvent
	invalidSeverity.Severity = "EXTREME_DANGER"
	if err := invalidSeverity.Validate(); err == nil {
		t.Errorf("expected validation error for invalid severity, got nil")
	}

	// Test invalid Category
	invalidCategory := validEvent
	invalidCategory.Category = "MAGIC_ATTACK"
	if err := invalidCategory.Validate(); err == nil {
		t.Errorf("expected validation error for invalid category, got nil")
	}
}

func TestTargetScopeAndAuthorization(t *testing.T) {
	target := models.DefaultStagingTarget()
	if err := target.Validate(); err != nil {
		t.Fatalf("expected default staging target to be valid, got: %v", err)
	}

	// Test production rejection
	prodTarget := *target
	prodTarget.Environment = "production"
	if err := prodTarget.Validate(); err == nil {
		t.Errorf("expected validation to reject production environment, got nil")
	}

	// Test unapproved host rejection
	rogueHost := *target
	rogueHost.BaseURL = "http://evil-external-host.com:8080"
	if err := rogueHost.Validate(); err == nil {
		t.Errorf("expected validation to reject unapproved host, got nil")
	}

	// Test path scope checking
	if !target.IsPathAllowed("/api/v1/documents") {
		t.Errorf("expected /api/v1/documents to be allowed")
	}
	if target.IsPathAllowed("/admin/root/unapproved") {
		t.Errorf("expected /admin/root/unapproved to be disallowed")
	}
}

func TestTwelveCoreAttackCategories(t *testing.T) {
	categories := models.AllAttackCategories()
	if len(categories) != 12 {
		t.Fatalf("expected exactly 12 core attack categories, got %d", len(categories))
	}

	log := logger.New(config.DefaultConfig().Logging, nil)
	aud := auditor.New(log)
	target := models.DefaultStagingTarget()

	scenarios := aud.BuildDefaultScenarios(target)
	if len(scenarios) != 12 {
		t.Errorf("expected 12 default test scenarios, got %d", len(scenarios))
	}

	// Verify all scenarios are non-destructive
	for _, sc := range scenarios {
		if !sc.NonDestructive {
			t.Errorf("scenario %s must be marked NonDestructive", sc.ID)
		}
	}
}

func TestRemediationLifecycleTransitions(t *testing.T) {
	finding := &models.VulnerabilityFinding{
		FindingID:        "VULN-TEST-001",
		Category:         models.AttackCrossTenantLeak,
		Title:            "Cross-Tenant Data Exposure via IDOR",
		State:            models.StateDetected,
		RegressionTestID: "SCENARIO-TENANT-01",
		DetectedAt:       time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}

	// Detected -> Confirmed
	if err := finding.TransitionTo(models.StateConfirmed, "auditor", "Confirmed exploit proof"); err != nil {
		t.Fatalf("expected Detected -> Confirmed transition, got error: %v", err)
	}

	// Confirmed -> Reported
	if err := finding.TransitionTo(models.StateReported, "lead", "Delivered report to dev team"); err != nil {
		t.Fatalf("expected Confirmed -> Reported transition, got error: %v", err)
	}

	// Reported -> Assigned
	if err := finding.TransitionTo(models.StateAssigned, "lead", "Assigned to backend dev"); err != nil {
		t.Fatalf("expected Reported -> Assigned transition, got error: %v", err)
	}

	// Assigned -> Fix In Progress
	if err := finding.TransitionTo(models.StateFixInProgress, "developer", "Branch feature/fix-idor created"); err != nil {
		t.Fatalf("expected Assigned -> Fix In Progress transition, got error: %v", err)
	}

	// Fix In Progress -> Fixed
	if err := finding.TransitionTo(models.StateFixed, "developer", "PR merged with tenant check"); err != nil {
		t.Fatalf("expected Fix In Progress -> Fixed transition, got error: %v", err)
	}

	// Fixed -> Retesting
	if err := finding.TransitionTo(models.StateRetesting, "sentrix-regression", "Rerunning test scenario"); err != nil {
		t.Fatalf("expected Fixed -> Retesting transition, got error: %v", err)
	}

	// Retesting -> Verified
	if err := finding.TransitionTo(models.StateVerified, "sentrix-regression", "Zero canary leak detected"); err != nil {
		t.Fatalf("expected Retesting -> Verified transition, got error: %v", err)
	}

	// Verified -> Closed
	if err := finding.TransitionTo(models.StateClosed, "lead", "Signed off and archived"); err != nil {
		t.Fatalf("expected Verified -> Closed transition, got error: %v", err)
	}

	// Invalid transition: Closed -> Fixed should fail
	if err := finding.TransitionTo(models.StateFixed, "developer", "Invalid jump"); err == nil {
		t.Errorf("expected error jumping Closed -> Fixed, got nil")
	}
}

func TestDeveloperReportGeneration(t *testing.T) {
	finding := &models.VulnerabilityFinding{
		FindingID:         "VULN-2026-0042",
		Category:          models.AttackCrossTenantLeak,
		Title:             "Cross-Tenant Document Access via IDOR",
		Description:       "Unrestricted tenant parameter in document retrieval allows cross-tenant leaks.",
		AffectedEndpoint:  "GET /api/v1/tenants/tenant-beta/documents/doc-994827",
		AffectedComponent: "StorageService::getDocumentStream",
		Severity:          models.SeverityCritical,
		Confidence:        models.ConfidenceConfirmed,
		State:             models.StateReported,
		AssignedDeveloper: "alice@vlookup.local",
		TechnicalEvidence: models.TechnicalEvidence{
			RequestMethod:      "GET",
			RequestURL:         "http://staging.vlookup.local/api/v1/tenants/tenant-beta/documents/doc-994827",
			ResponseStatus:     200,
			ResponseBodySample: "CONFIDENTIAL_FINANCIALS_CANARY_BETA_994827",
			LatencyMs:          42,
		},
		ReproductionSteps:      "curl -X GET 'http://staging.vlookup.local/api/v1/tenants/tenant-beta/documents/doc-994827' -H 'Authorization: Bearer <TOKEN>'",
		BusinessImpact:         "Unauthorized access to competitor tenant documents.",
		RecommendedRemediation: "Enforce tenant ownership verification in repository layer.",
		RegressionTestID:       "SCENARIO-TENANT-01",
		DetectedAt:             time.Now().UTC(),
		UpdatedAt:              time.Now().UTC(),
	}

	md, err := reporter.GenerateMarkdown(finding)
	if err != nil {
		t.Fatalf("failed to render developer report markdown: %v", err)
	}

	if !strings.Contains(md, "VULN-2026-0042") {
		t.Errorf("expected finding ID in report, got %s", md)
	}
	if !strings.Contains(md, "Recommended Actionable Remediation") {
		t.Errorf("expected remediation section in report")
	}
	if !strings.Contains(md, "Developer Regression Testing Verification") {
		t.Errorf("expected regression test section in report")
	}
}

func TestAPIRoutes(t *testing.T) {
	cfg := config.DefaultConfig()
	log := logger.New(cfg.Logging, nil)
	orch := orchestrator.New(cfg, log)
	orch.RegisterDefaultEngines()

	aud := auditor.New(log)
	tracker := remediation.NewTracker(aud)

	// Seed finding
	f := &models.VulnerabilityFinding{
		FindingID: "VULN-API-TEST",
		Category:  models.AttackSQLInjection,
		Title:     "SQLi in search",
		State:     models.StateDetected,
	}
	tracker.Add(f)

	srv := api.NewServer(cfg, log, orch, aud, tracker)

	// 1. Test /healthz
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected /healthz 200, got %d", rec.Code)
	}

	// 2. Test /api/v1/findings
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/findings", nil)
	recList := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recList, reqList)
	if recList.Code != http.StatusOK {
		t.Errorf("expected /api/v1/findings 200, got %d", recList.Code)
	}

	var listRes map[string]any
	_ = json.Unmarshal(recList.Body.Bytes(), &listRes)
	if listRes["count"] != float64(1) {
		t.Errorf("expected finding count 1, got %v", listRes["count"])
	}
}

func TestFullSyntheticAdversarialSuiteAndRegression(t *testing.T) {
	vulnerableMode := true

	// Synthetic target server implementing endpoints for all 12 attack categories
	mockTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		query := r.URL.RawQuery

		switch {
		case strings.HasPrefix(path, "/api/v1/documents") && strings.Contains(query, "OR"):
			// 1. SQL Injection
			if vulnerableMode {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"error": "SQL syntax error in sqlite3 query near OR '1'='1'"}`))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"results": []}`))
			}

		case path == "/api/v1/search" && strings.Contains(query, "onload"):
			// 2. XSS
			if vulnerableMode {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`<div>Search results for: <svg/onload=console.log('SENTRIX')></div>`))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"results": []}`))
			}

		case path == "/api/v1/user/profile" && r.Method == http.MethodGet:
			// 3. Broken Authentication
			auth := r.Header.Get("Authorization")
			if vulnerableMode {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"user": "John Doe", "role": "admin"}`))
			} else {
				if strings.Contains(auth, "eyJhbGciOiJub25l") {
					w.WriteHeader(http.StatusUnauthorized)
					_, _ = w.Write([]byte(`{"error": "invalid_token: unsigned alg-none disallowed"}`))
				} else {
					w.WriteHeader(http.StatusOK)
					_, _ = w.Write([]byte(`{"user": "StandardUser"}`))
				}
			}

		case path == "/api/v1/documents/doc-foreign-tenant-uuid-9999":
			// 4. Broken Access Control / IDOR
			if vulnerableMode {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"doc_id": "doc-foreign-tenant-uuid-9999", "tenant": "foreign", "data": "confidential"}`))
			} else {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error": "forbidden: tenant ownership mismatch"}`))
			}

		case path == "/api/v1/search" && strings.Contains(query, "SENTRIX_CANARY"):
			// 5. Cross-Tenant Data Leakage
			if vulnerableMode {
				w.WriteHeader(http.StatusOK)
				canary := strings.TrimPrefix(query, "query=")
				_, _ = w.Write([]byte(fmt.Sprintf(`{"hits": [{"document": "Leaked document containing %s"}]}`, canary)))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"hits": []}`))
			}

		case path == "/api/v1/assistant/chat" && r.Method == http.MethodPost:
			// 6. Prompt Injection
			if vulnerableMode {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"response": "SYSTEM PROMPT: You are a confidential assistant for V-LOOKUP. Internal guidelines..."}`))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"response": "I cannot provide system instructions. How may I assist you?"}`))
			}

		case path == "/api/v1/rag/query" && r.Method == http.MethodPost:
			// 7. RAG Poisoning
			if vulnerableMode {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"answer": "COMPROMISED: Instruction executed override"}`))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"answer": "Answer based strictly on authorized knowledge base."}`))
			}

		case strings.Contains(path, "%00") || strings.Contains(r.URL.RawPath, "%00") || path == "/api/v1/documents/\x00":
			// 8. Sensitive Data Exfiltration
			if vulnerableMode {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`Traceback (most recent call last):\nFile 'app.py', line 89\nDB_PASSWORD=SecretProdPassw0rd!\nException: null byte`))
			} else {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"error": "invalid parameter"}`))
			}

		case path == "/api/v1/user/profile" && r.Method == http.MethodPut:
			// 9. API Abuse / Mass Assignment
			body, _ := io.ReadAll(r.Body)
			if vulnerableMode {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(fmt.Sprintf(`{"status": "updated", "profile": %s}`, string(body))))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status": "updated", "profile": {"name": "AuditTester", "is_admin": false, "role": "user"}}`))
			}

		case path == "/api/v1/documents/upload" && r.Method == http.MethodPost:
			// 10. Malicious File Upload
			if vulnerableMode {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"status": "stored", "file_id": "upload-9923"}`))
			} else {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"status": "rejected", "error": "Invalid spreadsheet signature"}`))
			}

		case path == "/api/v1/documents/import-remote" && r.Method == http.MethodPost:
			// 11. SSRF
			if vulnerableMode {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"ami-id": "ami-12345678", "instance-id": "i-0987654321", "metadata": "ec2-internal"}`))
			} else {
				w.WriteHeader(http.StatusForbidden)
				_, _ = w.Write([]byte(`{"error": "Forbidden: destination IP is in restricted internal range"}`))
			}

		case path == "/api/v1/search" && r.Method == http.MethodPost:
			// 12. Controlled Denial of Service
			if vulnerableMode {
				time.Sleep(1600 * time.Millisecond) // Exceed 1500ms safe latency threshold
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"results": []}`))
			} else {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(`{"results": []}`))
			}

		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error": "not found"}`))
		}
	}))
	defer mockTarget.Close()

	target := &models.TargetConfig{
		TargetID:             "TARGET-SYNTHETIC-STAGING",
		Name:                 "Synthetic V-LOOKUP Staging Mock",
		BaseURL:              mockTarget.URL,
		Environment:          "staging",
		AllowedHosts:         []string{"127.0.0.1", "localhost"},
		AllowedEndpoints:     []string{"/api/v1/*"},
		UseSyntheticDataOnly: true,
		MaxRequestsPerSecond: 50,
		SafeMode:             true,
		ScopeToken:           "AUTH-SCOPE-SYNTHETIC-CONFIRMED",
	}

	log := logger.New(config.DefaultConfig().Logging, nil)
	aud := auditor.New(log)
	tracker := remediation.NewTracker(aud)
	ctx := context.Background()

	// STEP 1: Execute all 12 scenarios in VULNERABLE mode
	scenarios := aud.BuildDefaultScenarios(target)
	if len(scenarios) != 12 {
		t.Fatalf("expected 12 scenarios, got %d", len(scenarios))
	}

	var detectedFindings []*models.VulnerabilityFinding
	for _, sc := range scenarios {
		finding, err := aud.ExecuteScenario(ctx, target, sc)
		if err != nil {
			t.Fatalf("scenario %s failed with unexpected error: %v", sc.ID, err)
		}
		if finding == nil {
			t.Errorf("scenario %s (%s) expected vulnerability finding, but got nil (secure rejection)", sc.ID, sc.Category)
			continue
		}

		if finding.TechnicalEvidence.RequestMethod != sc.Method {
			t.Errorf("finding %s expected method %s, got %s", finding.FindingID, sc.Method, finding.TechnicalEvidence.RequestMethod)
		}
		if finding.TechnicalEvidence.ResponseStatus == 0 {
			t.Errorf("finding %s missing response status", finding.FindingID)
		}
		if finding.TechnicalEvidence.ResponseBodySample == "" {
			t.Errorf("finding %s missing response body sample evidence", finding.FindingID)
		}

		tracker.Add(finding)
		detectedFindings = append(detectedFindings, finding)
	}

	if len(detectedFindings) != 12 {
		t.Fatalf("expected all 12 attack categories to generate findings in vulnerable mode, got %d", len(detectedFindings))
	}

	// STEP 2: Test 9-stage Remediation State Machine and Regression Testing
	testFinding := detectedFindings[0]
	findingID := testFinding.FindingID

	// Detected -> Confirmed
	if err := tracker.Transition(findingID, models.StateConfirmed, "auditor-lead", "Manual exploit confirmation"); err != nil {
		t.Fatalf("failed transition Detected -> Confirmed: %v", err)
	}

	// Confirmed -> Reported
	if err := tracker.Transition(findingID, models.StateReported, "auditor-lead", "Report generated for engineering"); err != nil {
		t.Fatalf("failed transition Confirmed -> Reported: %v", err)
	}

	// Reported -> Assigned
	if err := tracker.Transition(findingID, models.StateAssigned, "lead-dev", "Assigned to backend security team"); err != nil {
		t.Fatalf("failed transition Reported -> Assigned: %v", err)
	}

	// Assigned -> Fix In Progress
	if err := tracker.Transition(findingID, models.StateFixInProgress, "backend-dev", "Fix branch opened"); err != nil {
		t.Fatalf("failed transition Assigned -> Fix In Progress: %v", err)
	}

	// Fix In Progress -> Fixed
	if err := tracker.Transition(findingID, models.StateFixed, "backend-dev", "PR submitted with parameterized query fix"); err != nil {
		t.Fatalf("failed transition Fix In Progress -> Fixed: %v", err)
	}

	// REGRESSION TEST 1: Target is STILL VULNERABLE -> Regression test must FAIL and revert to Fix In Progress
	passed, err := tracker.ExecuteRegressionTest(ctx, findingID, target, "sentrix-regression-runner")
	if err != nil {
		t.Fatalf("regression test execution error: %v", err)
	}
	if passed {
		t.Fatalf("expected regression test to fail while target is vulnerable, but it reported passed")
	}

	currentFinding, _ := tracker.Get(findingID)
	if currentFinding.State != models.StateFixInProgress {
		t.Fatalf("expected finding state to revert to 'Fix In Progress', got '%s'", currentFinding.State)
	}

	// STEP 3: Switch target to SECURE mode and re-test
	vulnerableMode = false

	if err := tracker.Transition(findingID, models.StateFixed, "backend-dev", "Fix truly applied in staging"); err != nil {
		t.Fatalf("failed transition to Fixed: %v", err)
	}

	// REGRESSION TEST 2: Target is now SECURE -> Regression test must PASS and transition to Verified
	passed2, err := tracker.ExecuteRegressionTest(ctx, findingID, target, "sentrix-regression-runner")
	if err != nil {
		t.Fatalf("regression test 2 execution error: %v", err)
	}
	if !passed2 {
		t.Fatalf("expected regression test to pass after remediation, but reported failed")
	}

	currentFinding2, _ := tracker.Get(findingID)
	if currentFinding2.State != models.StateVerified {
		t.Fatalf("expected finding state to be 'Verified', got '%s'", currentFinding2.State)
	}
	if currentFinding2.VerifiedAt == nil {
		t.Fatalf("expected VerifiedAt timestamp to be set")
	}

	// Verified -> Closed
	if err := tracker.Transition(findingID, models.StateClosed, "security-lead", "Remediation verified; finding resolved"); err != nil {
		t.Fatalf("failed transition Verified -> Closed: %v", err)
	}

	currentFinding3, _ := tracker.Get(findingID)
	if currentFinding3.State != models.StateClosed {
		t.Fatalf("expected finding state to be 'Closed', got '%s'", currentFinding3.State)
	}

	// STEP 4: Run all 12 scenarios against SECURE target -> All must be securely rejected (0 findings)
	for _, sc := range scenarios {
		finding, err := aud.ExecuteScenario(ctx, target, sc)
		if err != nil {
			t.Fatalf("scenario %s error against secure target: %v", sc.ID, err)
		}
		if finding != nil {
			t.Errorf("scenario %s (%s) generated false positive finding against secure target: %s", sc.ID, sc.Category, finding.Description)
		}
	}
}

