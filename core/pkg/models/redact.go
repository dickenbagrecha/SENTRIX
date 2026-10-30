// Package models provides canonical security data models and redaction utilities.
package models

import (
	"regexp"
	"strings"
)

var (
	// jwtRegex matches JSON Web Tokens with 3 segments separated by dots
	jwtRegex = regexp.MustCompile(`\beyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]*\b`)

	// bearerRegex matches Bearer authorization tokens
	bearerRegex = regexp.MustCompile(`(?i)\b(Bearer\s+)[A-Za-z0-9\-\._~+/]+=*`)

	// basicAuthRegex matches Basic auth headers
	basicAuthRegex = regexp.MustCompile(`(?i)\b(Basic\s+)[A-Za-z0-9+/=]+`)

	// keyValueSecretsRegex matches passwords, tokens, API keys in json, env, and query strings
	keyValueSecretsRegex = regexp.MustCompile(`(?i)("(?:password|passwd|secret|secret_key|api_key|access_key|private_key|token|auth_token|db_password)"\s*:\s*)"([^"]+)"`)
	plainKVSecretsRegex  = regexp.MustCompile(`(?i)\b((?:password|passwd|secret|secret_key|api_key|access_key|private_key|token|auth_token|db_password)\s*[:=]\s*)([^\s"',;]+)`)

	// cookieValuesRegex matches session cookies
	cookieValuesRegex = regexp.MustCompile(`(?i)\b((?:session|sessionid|token|auth|jwt|connect\.sid)=)([^\s;]+)`)

	// dbUriRegex matches database connection strings containing credentials
	dbUriRegex = regexp.MustCompile(`([a-zA-Z0-9+]+://)([^:]+):([^@]+)@`)
)

// RedactSensitiveData masks credentials, tokens, session cookies and secrets from raw strings.
func RedactSensitiveData(input string) string {
	if input == "" {
		return ""
	}

	result := input

	// 1. Redact DB URIs
	result = dbUriRegex.ReplaceAllString(result, "${1}${2}:[REDACTED_CREDENTIALS]@")

	// 2. Redact Bearer and Basic headers
	result = bearerRegex.ReplaceAllString(result, "${1}[REDACTED_TOKEN]")
	result = basicAuthRegex.ReplaceAllString(result, "${1}[REDACTED_AUTH]")

	// 3. Redact standalone JWTs
	result = jwtRegex.ReplaceAllString(result, "[REDACTED_JWT]")

	// 4. Redact JSON key-value secrets
	result = keyValueSecretsRegex.ReplaceAllString(result, `${1}"[REDACTED_SECRET]"`)

	// 5. Redact plain key=value secrets
	result = plainKVSecretsRegex.ReplaceAllString(result, `${1}[REDACTED_SECRET]`)

	// 6. Redact session cookies
	result = cookieValuesRegex.ReplaceAllString(result, "${1}[REDACTED_COOKIE]")

	return result
}

// RedactHeaders produces a copy of HTTP headers with sensitive fields redacted for reporting.
func RedactHeaders(headers map[string]string) map[string]string {
	if headers == nil {
		return nil
	}
	redacted := make(map[string]string, len(headers))
	for k, v := range headers {
		lowerKey := strings.ToLower(k)
		switch {
		case lowerKey == "authorization":
			if strings.HasPrefix(strings.ToLower(v), "bearer ") {
				redacted[k] = "Bearer [REDACTED_TOKEN]"
			} else if strings.HasPrefix(strings.ToLower(v), "basic ") {
				redacted[k] = "Basic [REDACTED_AUTH]"
			} else {
				redacted[k] = "[REDACTED_AUTH]"
			}
		case lowerKey == "cookie":
			redacted[k] = cookieValuesRegex.ReplaceAllString(v, "${1}[REDACTED_COOKIE]")
		case lowerKey == "set-cookie":
			redacted[k] = cookieValuesRegex.ReplaceAllString(v, "${1}[REDACTED_COOKIE]")
		case strings.Contains(lowerKey, "token") || strings.Contains(lowerKey, "secret") || strings.Contains(lowerKey, "api-key"):
			redacted[k] = "[REDACTED_KEY]"
		default:
			redacted[k] = RedactSensitiveData(v)
		}
	}
	return redacted
}

// Sanitize cleans all sensitive fields in the finding before persisting or publishing.
func (f *VulnerabilityFinding) Sanitize() {
	if f == nil {
		return
	}
	f.TechnicalEvidence.ResponseBodySample = RedactSensitiveData(f.TechnicalEvidence.ResponseBodySample)
	f.TechnicalEvidence.RequestBody = RedactSensitiveData(f.TechnicalEvidence.RequestBody)
	f.ReproductionSteps = RedactSensitiveData(f.ReproductionSteps)
}
