// Package remediation manages the 9-stage vulnerability tracking lifecycle and regression testing.
package remediation

import (
	"context"
	"fmt"
	"sync"
	"time"

	"sentrix/core/internal/auditor"
	"sentrix/core/pkg/models"
)

// Tracker provides thread-safe management of vulnerability findings and regression verification.
type Tracker struct {
	mu       sync.RWMutex
	findings map[string]*models.VulnerabilityFinding
	auditor  *auditor.Auditor
}

// NewTracker creates an initialized finding tracker.
func NewTracker(auditor *auditor.Auditor) *Tracker {
	return &Tracker{
		findings: make(map[string]*models.VulnerabilityFinding),
		auditor:  auditor,
	}
}

// Add stores a new vulnerability finding in the tracker.
func (t *Tracker) Add(finding *models.VulnerabilityFinding) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.findings[finding.FindingID] = finding
}

// Get retrieves a finding by its ID.
func (t *Tracker) Get(findingID string) (*models.VulnerabilityFinding, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	f, ok := t.findings[findingID]
	return f, ok
}

// List returns all findings, optionally filtered by state.
func (t *Tracker) List(filterState *models.RemediationState) []*models.VulnerabilityFinding {
	t.mu.RLock()
	defer t.mu.RUnlock()

	var results []*models.VulnerabilityFinding
	for _, f := range t.findings {
		if filterState == nil || f.State == *filterState {
			results = append(results, f)
		}
	}
	return results
}

// Transition updates the remediation lifecycle state of a finding with audit history.
func (t *Tracker) Transition(findingID string, newState models.RemediationState, actor string, comment string) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	f, ok := t.findings[findingID]
	if !ok {
		return fmt.Errorf("finding '%s' not found", findingID)
	}

	return f.TransitionTo(newState, actor, comment)
}

// ExecuteRegressionTest re-runs the specific scenario associated with a finding to verify remediation.
func (t *Tracker) ExecuteRegressionTest(ctx context.Context, findingID string, target *models.TargetConfig, actor string) (bool, error) {
	t.mu.Lock()
	f, ok := t.findings[findingID]
	if !ok {
		t.mu.Unlock()
		return false, fmt.Errorf("finding '%s' not found", findingID)
	}

	// Move to Retesting state if currently Fixed
	if f.State == models.StateFixed {
		_ = f.TransitionTo(models.StateRetesting, actor, "Initiating automated regression re-test")
	}
	t.mu.Unlock()

	// Locate the matching test scenario
	scenarios := t.auditor.BuildDefaultScenarios(target)
	var targetScenario *models.TestScenario
	for _, sc := range scenarios {
		if sc.ID == f.RegressionTestID {
			targetScenario = &sc
			break
		}
	}

	if targetScenario == nil {
		return false, fmt.Errorf("regression test scenario '%s' not found in test suite", f.RegressionTestID)
	}

	// Re-run probe
	newFinding, err := t.auditor.ExecuteScenario(ctx, target, *targetScenario)
	if err != nil {
		return false, fmt.Errorf("regression test execution error: %w", err)
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	if newFinding != nil {
		// Exploit still triggers! Regression test failed
		_ = f.TransitionTo(models.StateFixInProgress, "sentrix-regression-engine",
			fmt.Sprintf("Regression test FAILED: Exploit reproduced with status %d", newFinding.TechnicalEvidence.ResponseStatus))
		return false, nil
	}

	// Exploit no longer triggers! Remediation verified
	now := time.Now().UTC()
	f.VerifiedAt = &now
	_ = f.TransitionTo(models.StateVerified, "sentrix-regression-engine",
		"Regression test PASSED: Vulnerability successfully mitigated without side-effects")
	return true, nil
}
