// Package models defines the canonical data structures for SENTRIX,
// including the SENTRIX Common Security Event (SCSE) specification.
package models

import (
	"errors"
	"fmt"
	"regexp"
	"time"
)

// Severity represents normalized threat severity levels.
type Severity string

const (
	SeverityCritical      Severity = "CRITICAL"
	SeverityHigh          Severity = "HIGH"
	SeverityMedium        Severity = "MEDIUM"
	SeverityLow           Severity = "LOW"
	SeverityInformational Severity = "INFORMATIONAL"
)

// Category represents high-level security domains.
type Category string

const (
	CategoryWebAttack         Category = "WEB_APPLICATION_ATTACK"
	CategoryNetworkIntrusion  Category = "NETWORK_INTRUSION"
	CategoryHostAnomaly       Category = "HOST_ENDPOINT_ANOMALY"
	CategoryFIMViolation      Category = "FILE_INTEGRITY_VIOLATION"
	CategoryVulnerabilityCVE  Category = "VULNERABILITY_CVE"
	CategoryPromptInjection   Category = "AI_PROMPT_INJECTION"
	CategoryJailbreak         Category = "AI_JAILBREAK"
	CategoryDataLeak          Category = "AI_DATA_LEAK"
	CategoryPolicyViolation   Category = "POLICY_VIOLATION"
)

// ActionTaken represents the mitigation or defense action applied.
type ActionTaken string

const (
	ActionBlocked    ActionTaken = "BLOCKED"
	ActionDropped    ActionTaken = "DROPPED"
	ActionAlerted    ActionTaken = "ALERTED"
	ActionRemediated ActionTaken = "REMEDIATED"
	ActionLogged     ActionTaken = "LOGGED"
	ActionPassed     ActionTaken = "PASSED"
)

// EngineSource identifies which detection engine originated the telemetry.
type EngineSource string

const (
	EngineCoraza      EngineSource = "coraza"
	EngineCrowdSec    EngineSource = "crowdsec"
	EngineModSecurity EngineSource = "modsecurity"
	EnginePromptfoo   EngineSource = "promptfoo"
	EngineWazuh       EngineSource = "wazuh"
	EngineCore        EngineSource = "sentrix-core"
)

// EndpointDetails describes network or resource targets.
type EndpointDetails struct {
	IP        string `json:"ip,omitempty"`
	Port      int    `json:"port,omitempty"`
	Hostname  string `json:"hostname,omitempty"`
	User      string `json:"user,omitempty"`
	Country   string `json:"country,omitempty"`
	URL       string `json:"url,omitempty"`
	Endpoint  string `json:"endpoint,omitempty"`
	FilePath  string `json:"file_path,omitempty"`
	LLMModel  string `json:"llm_model,omitempty"`
}

// MitreAttack defines MITRE ATT&CK framework mapping.
type MitreAttack struct {
	Tactic        string `json:"tactic,omitempty"`
	TechniqueID   string `json:"technique_id,omitempty"`
	TechniqueName string `json:"technique_name,omitempty"`
}

// ThreatDetails contains fine-grained signatures, rules, and scoring.
type ThreatDetails struct {
	RuleID          string       `json:"rule_id,omitempty"`
	RuleName        string       `json:"rule_name,omitempty"`
	CVE             string       `json:"cve,omitempty"`
	CWE             string       `json:"cwe,omitempty"`
	MitreAttack     *MitreAttack `json:"mitre_attack,omitempty"`
	OwaspCategory   string       `json:"owasp_category,omitempty"`
	ConfidenceScore float64      `json:"confidence_score,omitempty"`
}

// SCSEEvent represents a normalized SENTRIX Common Security Event.
type SCSEEvent struct {
	EventID       string          `json:"event_id"`
	Timestamp     time.Time       `json:"timestamp"`
	Engine        EngineSource    `json:"engine"`
	Severity      Severity        `json:"severity"`
	Category      Category        `json:"category"`
	ActionTaken   ActionTaken     `json:"action_taken"`
	Source        EndpointDetails `json:"source"`
	Target        EndpointDetails `json:"target"`
	ThreatDetails *ThreatDetails  `json:"threat_details,omitempty"`
	RawEvent      any             `json:"raw_event,omitempty"`
}

var uuidRegex = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)

// Validate checks that all required SCSE fields are present and valid.
func (e *SCSEEvent) Validate() error {
	if e.EventID == "" {
		return errors.New("event_id is required")
	}
	if !uuidRegex.MatchString(e.EventID) {
		return fmt.Errorf("event_id '%s' is not a valid UUID", e.EventID)
	}
	if e.Timestamp.IsZero() {
		return errors.New("timestamp must not be zero")
	}
	if e.Engine == "" {
		return errors.New("engine is required")
	}

	switch e.Severity {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInformational:
		// Valid
	default:
		return fmt.Errorf("invalid severity level: '%s'", e.Severity)
	}

	switch e.Category {
	case CategoryWebAttack, CategoryNetworkIntrusion, CategoryHostAnomaly,
		CategoryFIMViolation, CategoryVulnerabilityCVE, CategoryPromptInjection,
		CategoryJailbreak, CategoryDataLeak, CategoryPolicyViolation:
		// Valid
	default:
		return fmt.Errorf("invalid category: '%s'", e.Category)
	}

	switch e.ActionTaken {
	case ActionBlocked, ActionDropped, ActionAlerted, ActionRemediated, ActionLogged, ActionPassed:
		// Valid
	default:
		return fmt.Errorf("invalid action_taken: '%s'", e.ActionTaken)
	}

	return nil
}
