package models

// AttackCategory represents one of the 12 core security attack domains tested by SENTRIX.
type AttackCategory string

const (
	AttackSQLInjection       AttackCategory = "SQL_INJECTION"
	AttackXSS                AttackCategory = "CROSS_SITE_SCRIPTING"
	AttackBrokenAuth         AttackCategory = "BROKEN_AUTHENTICATION"
	AttackIDOR               AttackCategory = "BROKEN_ACCESS_CONTROL_IDOR"
	AttackCrossTenantLeak    AttackCategory = "CROSS_TENANT_DATA_LEAKAGE"
	AttackPromptInjection    AttackCategory = "PROMPT_INJECTION"
	AttackRAGPoisoning       AttackCategory = "RAG_POISONING"
	AttackDataExfiltration   AttackCategory = "SENSITIVE_DATA_EXFILTRATION"
	AttackAPIAbuse           AttackCategory = "API_ABUSE"
	AttackFileUpload         AttackCategory = "MALICIOUS_FILE_UPLOAD"
	AttackSSRF               AttackCategory = "SSRF"
	AttackDenialOfService    AttackCategory = "DENIAL_OF_SERVICE"
)

// AllAttackCategories returns a slice of all 12 mandatory attack categories.
func AllAttackCategories() []AttackCategory {
	return []AttackCategory{
		AttackSQLInjection,
		AttackXSS,
		AttackBrokenAuth,
		AttackIDOR,
		AttackCrossTenantLeak,
		AttackPromptInjection,
		AttackRAGPoisoning,
		AttackDataExfiltration,
		AttackAPIAbuse,
		AttackFileUpload,
		AttackSSRF,
		AttackDenialOfService,
	}
}

// TestScenario defines a specific, controlled probe or adversarial test case.
type TestScenario struct {
	ID             string         `json:"id"`
	Category       AttackCategory `json:"category"`
	Name           string         `json:"name"`
	Description    string         `json:"description"`
	Method         string         `json:"method"` // GET, POST, PUT, DELETE
	RelativePath   string         `json:"relative_path"`
	Payload        string         `json:"payload,omitempty"`
	Headers        map[string]string `json:"headers,omitempty"`
	NonDestructive bool           `json:"non_destructive"`
	CanaryToken    string         `json:"canary_token,omitempty"`
	EngineMapping  EngineSource   `json:"engine_mapping"`
}
