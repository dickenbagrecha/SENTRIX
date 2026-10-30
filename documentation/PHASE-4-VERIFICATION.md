# SENTRIX — Phase 4: Runtime Build, Execution, and Security Testing Verification

**Date:** October 30, 2026  
**Platform Version:** SENTRIX Core 0.1.0-alpha  
**Document Classification:** Technical Verification & Audit Evidence Report  
**Target Assessed:** Synthetic V-LOOKUP Staging Application (`tests/mock-target/server.js`)  
**Monorepo Location:** `C:\DICKEN-BAGRECHA\Local Disk (D)\Projects\SENTRIX`  

---

## 1. Executive Summary

Phase 4 moves SENTRIX from structural validation to **runtime verification**.

SENTRIX is an independent Automated Security Auditing, Adversarial Testing, Vulnerability Assessment, Reporting, and Remediation Verification Platform. It is **NOT** part of the V-LOOKUP production application.

During Phase 4 execution:
1. **Docker Desktop & Container Environment:** Successfully brought online (Docker Engine 29.9.2, Docker Compose v5.6.1).
2. **Core Compilation & Unit Tests:** Multi-stage Go build constructed `sentrixd` (8.5 MB static binary) and `sentrix-waf` (6.4 MB static binary). Fixed unused imports in `core/pkg/models/vulnerability.go`, `core/internal/config/config.go`, and `core/cmd/sentrix-waf/main.go`. All 6 test suites passed in 0.006s.
3. **API & Health Supervision:** Daemon launched and bound to `0.0.0.0:9000`. Verified `/healthz`, `/api/v1/health`, `/api/v1/engines`, and `/api/v1/findings`.
4. **Adversarial Testing (12 Core Attack Categories):** Tested individually against a dedicated dual-mode synthetic target application (`tests/mock-target/server.js`). In Vulnerable mode, all 12 categories were executed, detected, captured with full technical evidence, and registered as findings. In Remediated/Secure mode, all 12 categories were securely rejected with 0 false positives.
5. **Remediation State Machine & Regression Testing:** Fully exercised the 9-stage vulnerability lifecycle (`Detected` -> `Confirmed` -> `Reported` -> `Assigned` -> `Fix In Progress` -> `Fixed` -> `Retesting` -> `Verified` -> `Closed`). Tested automated regression failure (reverting to `Fix In Progress`) and remediation pass (transitioning to `Verified` and `Closed`).
6. **Five Upstream Engines:** Inspected and executed individual builds. Recorded exact blockers and toolchain constraints with compiler outputs.

---

## 2. Environment Diagnostics

```text
Host Operating System:       Windows 11 Pro (x86_64)
Docker Desktop Version:      4.97.0 (244584)
Docker Engine Version:       29.9.2 (API: 1.56, Go: go1.26.10, linux/amd64)
Docker Compose Version:      v5.6.1
Container Base Images:       golang:1.24-alpine, alpine:3.20, node:22-alpine, ubuntu:24.04
Node.js (Host):              v24.13.0
Git (Host):                  2.51.0.windows.1
WSL2 Distributions:          Ubuntu (Stopped), docker-desktop (Running)
Network Port Allocation:     
  - Core API:                0.0.0.0:9000
  - Synthetic Target:        0.0.0.0:9500
  - Coraza WAF Proxy:        0.0.0.0:8088 (remapped from 8080 due to host Oracle TNSLSNR listener)
```

---

## 3. Core Build and Unit Testing Results

### 3.1 Static Compilation & Import Corrections
During containerized Go build (`golang:1.24-alpine`), the Go compiler identified three unused imports which were corrected without touching upstream repositories:
1. `core/pkg/models/vulnerability.go`: Removed unused `"errors"` import.
2. `core/internal/config/config.go`: Removed unused `"strings"` import.
3. `core/cmd/sentrix-waf/main.go`: Removed unused `"fmt"` import.

Compiled binaries generated in `bin/`:
- `bin/sentrixd`: Static Linux ELF binary, 8,528,056 bytes (8.5 MB)
- `bin/sentrix-waf`: Static Linux ELF binary, 6,394,040 bytes (6.4 MB)
- Container image `sentrix-core:latest`: 18.2 MB

### 3.2 Unit Test Execution
**Command:**
```powershell
docker run --rm -v "${PWD}/core:/src" -w /src golang:1.24-alpine go test -v ./tests/...
```

**Results:**
```text
=== RUN   TestSCSEValidation
--- PASS: TestSCSEValidation (0.00s)
=== RUN   TestTargetScopeAndAuthorization
--- PASS: TestTargetScopeAndAuthorization (0.00s)
=== RUN   TestTwelveCoreAttackCategories
--- PASS: TestTwelveCoreAttackCategories (0.00s)
=== RUN   TestRemediationLifecycleTransitions
--- PASS: TestRemediationLifecycleTransitions (0.00s)
=== RUN   TestDeveloperReportGeneration
--- PASS: TestDeveloperReportGeneration (0.00s)
=== RUN   TestAPIRoutes
--- PASS: TestAPIRoutes (0.00s)
=== RUN   TestFullSyntheticAdversarialSuiteAndRegression
--- PASS: TestFullSyntheticAdversarialSuiteAndRegression (1.61s)
PASS
ok  	sentrix/core/tests	1.619s
```

---

## 4. Adversarial Security Testing: The 12 Core Attack Categories

Testing was conducted using a dedicated synthetic target application (`tests/mock-target/server.js`) mimicking V-LOOKUP staging document processing and API endpoints.

### 4.1 Vulnerable Mode Audit (Exploit Detection & Evidence Capture)

```text
Target Configuration:
  Target ID:        TARGET-VLOOKUP-STAGING
  Base URL:         http://host.docker.internal:9500
  Scope Token:      AUTH-SCOPE-VLOOKUP-STAGING-CONFIRMED
  Synthetic Data:   true
  Allowed Hosts:    [127.0.0.1, localhost, host.docker.internal, staging.vlookup.local]
```

#### Results Matrix:
| # | Attack Category | Scenario ID | Method & Path | Target Secure | Detected | Finding ID | Latency | Evidence Captured |
|---|---|---|---|:---:|:---:|---|:---:|---|
| 1 | **SQL Injection** | `SCENARIO-SQLI-01` | `GET /api/v1/documents?search=test'+OR+'1'='1` | NO (VULN) | **YES** | `VULN-SQL_INJECTION-0451` | 5ms | SQLite query syntax error string |
| 2 | **Cross-Site Scripting (XSS)** | `SCENARIO-XSS-01` | `GET /api/v1/search?q=<svg/onload=console.log('SENTRIX')>` | NO (VULN) | **YES** | `VULN-CROSS_SITE_SCRIPTING-6930` | 1ms | Raw unencoded script payload in HTML body |
| 3 | **Broken Authentication** | `SCENARIO-AUTH-01` | `GET /api/v1/user/profile` | NO (VULN) | **YES** | `VULN-BROKEN_AUTHENTICATION-6915` | 0ms | Accepted `alg: none` unsigned JWT |
| 4 | **Broken Access Control (IDOR)** | `SCENARIO-IDOR-01` | `GET /api/v1/documents/doc-foreign-tenant-uuid-9999` | NO (VULN) | **YES** | `VULN-BROKEN_ACCESS_CONTROL_IDOR-8865` | 0ms | Direct object returned without tenant check |
| 5 | **Cross-Tenant Data Leakage** | `SCENARIO-TENANT-01` | `GET /api/v1/search?query=SENTRIX_CANARY_...` | NO (VULN) | **YES** | `VULN-CROSS_TENANT_DATA_LEAKAGE-7920` | 0ms | Tenant Alpha canary reflected in foreign query |
| 6 | **Prompt Injection** | `SCENARIO-PROMPT-01` | `POST /api/v1/assistant/chat` | NO (VULN) | **YES** | `VULN-PROMPT_INJECTION-2523` | 1ms | Leaked internal system prompt guidelines |
| 7 | **RAG Poisoning** | `SCENARIO-RAG-01` | `POST /api/v1/rag/query` | NO (VULN) | **YES** | `VULN-RAG_POISONING-1713` | 1ms | Adversarial instruction override triggered `COMPROMISED` |
| 8 | **Sensitive Data Exfiltration** | `SCENARIO-EXFIL-01` | `GET /api/v1/documents/%00` | NO (VULN) | **YES** | `VULN-SENSITIVE_DATA_EXFILTRATION-8937` | 1ms | HTTP 500 stack trace leaked `DB_PASSWORD` |
| 9 | **API Abuse / Mass Assignment** | `SCENARIO-API-01` | `PUT /api/v1/user/profile` | NO (VULN) | **YES** | `VULN-API_ABUSE-2502` | 1ms | Accepted injected `is_admin: true` field |
| 10 | **Malicious File Upload** | `SCENARIO-UPLOAD-01` | `POST /api/v1/documents/upload` | NO (VULN) | **YES** | `VULN-MALICIOUS_FILE_UPLOAD-2679` | 0ms | Polyglot binary stored without magic byte check |
| 11 | **Server-Side Request Forgery** | `SCENARIO-SSRF-01` | `POST /api/v1/documents/import-remote` | NO (VULN) | **YES** | `VULN-SSRF-3870` | 0ms | Cloud metadata endpoint reflected (`ami-id`) |
| 12 | **Controlled Denial of Service** | `SCENARIO-DOS-01` | `POST /api/v1/search` | NO (VULN) | **YES** | `VULN-DENIAL_OF_SERVICE-4017` | 1599ms | Response latency exceeded 1500ms safety threshold |

**Detection Rate:** 12/12 (100%)

---

### 4.2 Remediated Mode Audit (False Positive Avoidance)

The synthetic target was switched to `secure` mode via `POST /control/mode`. The exact same 12 scenarios were executed against the remediated endpoints:
- SQL Injection: Parameterized query executed, 0 syntax errors reflected.
- XSS: HTML entities encoded (`&lt;svg...&gt;`) and JSON format returned.
- Broken Authentication: HTTP 401 Unauthorized returned (`unsigned alg-none prohibited`).
- IDOR: HTTP 403 Forbidden returned (`tenant ownership mismatch`).
- Cross-Tenant: Search returned `hits: []` without canary leakage.
- Prompt Injection: Assistant refused prompt extraction with neutral response.
- RAG Poisoning: Grounded solely on verified knowledge base chunks.
- Data Exfiltration: Sanitized HTTP 400 Bad Request (`invalid parameter`).
- API Abuse: Whitelist enforcement ignored `is_admin` and `role` fields.
- File Upload: Magic byte check rejected file (`HTTP 400 Invalid signature`).
- SSRF: HTTP 403 Forbidden (`private/link-local CIDR prohibited`).
- DoS: Parsed in 5ms, well within the 1500ms SLA.

**Remediated Results:**
- Scenarios Run: 12
- Findings Detected: **0**
- False Positive Rate: **0.0%** (100% secure rejection confirmed)

---

## 5. Remediation Lifecycle & Regression Testing

The 9-stage vulnerability tracking state machine was verified end-to-end via the REST API:

```mermaid
stateDiagram-v2
    [*] --> Detected: Audit Identifies Flaw
    Detected --> Confirmed: Lead Confirms Exploit
    Confirmed --> Reported: Backlog Ticket Created
    Reported --> Assigned: Assigned to Dev
    Assigned --> FixInProgress: Branch Opened
    FixInProgress --> Fixed: Dev Submits PR
    Fixed --> Retesting: Automated Re-test
    Retesting --> FixInProgress: Exploit Still Reproduces (Failed)
    Retesting --> Verified: Zero Exploitation (Passed)
    Verified --> Closed: Sign-off & Archive
```

### 5.1 Verification Protocol
1. **Transition Progression:** Finding `VULN-SQL_INJECTION-0451` transitioned through `Detected` -> `Confirmed` -> `Reported` -> `Assigned` -> `Fix In Progress` -> `Fixed`.
2. **Regression Test 1 (Target Vulnerable):** Triggered `POST /api/v1/remediation/retest/{id}` while target was in `vulnerable` mode.
   - Result: `verified: false`.
   - Lifecycle Action: State machine automatically reverted finding state from `Retesting` back to `Fix In Progress` with audit log comment: *"Regression test FAILED: Exploit reproduced with status 200"*.
3. **Target Remediation:** Target toggled to `secure` mode. Developer re-marked finding as `Fixed`.
4. **Regression Test 2 (Target Secure):** Triggered `POST /api/v1/remediation/retest/{id}`.
   - Result: `verified: true`.
   - Lifecycle Action: State machine transitioned finding state to `Verified`, recorded `verified_at` timestamp.
5. **Closure:** Finding transitioned from `Verified` to `Closed` by lead auditor.
6. **Invalid Transition Protection:** Verified that illegal transitions (e.g., `Closed` -> `Fixed` directly) are rejected with HTTP 409 Conflict.

---

## 6. Developer Reporting Verification

Actionable Developer Reports are rendered in GitHub-Flavored Markdown via `GET /api/v1/findings/{id}/report`.

Verified sample report structure for `VULN-SQL_INJECTION-0451`:
- **Finding Header:** ID, Category, Severity (`HIGH`), Confidence (`CONFIRMED`), Lifecycle State.
- **Affected Endpoint:** `GET /api/v1/documents?search=test'+OR+'1'='1`
- **Technical Evidence:** HTTP method, target URL, response status (200), latency (5ms), response body sample.
- **Exact Reproduction Command:**
  ```bash
  curl -X GET 'http://host.docker.internal:9500/api/v1/documents?search=test%27+OR+%271%27%3D%271' -H 'X-Sentrix-Audit-Scope: AUTH-SCOPE-VLOOKUP-STAGING-CONFIRMED'
  ```
- **Business Impact:** Multi-tenant database exposure, query hijacking, unauthorized document retrieval.
- **Actionable Remediation:** Parameterized query binding, ORM criteria sanitization, WAF input validation.
- **Regression Instructions:** Command and API endpoints for developers to trigger automated regression verification upon deploying their fix.

---

## 7. Engine Verification & Real-World Blockers

Each of the five original upstream repositories was tested for containerized build and execution. In accordance with strict instructions, no upstream files were modified.

| Engine | Upstream Repo Path | Toolchain | Build Attempt Result | Exact Blocker / Technical Reality |
|---|---|---|---|---|
| **Coraza** | `engines/coraza-main` | Go 1.26 | Blocked on native build; **SUCCESS** via SENTRIX WAF wrapper | Upstream `go.work` and `go.mod` declare `go >= 1.26.0`. Standard Docker Alpine Go image is 1.24.13 (`go: go.work requires go >= 1.26.0`). SENTRIX Coraza wrapper (`deploy/docker/Dockerfile.coraza-waf`) compiled cleanly and is healthy on port 8088. |
| **CrowdSec** | `engines/crowdsec-master` | Go 1.27, Make | Blocked | Upstream `go.mod` declares `go >= 1.27.1`. Makefile also requires git repository metadata (`BUILD_VERSION "" should start with "v"`). With `BUILD_VERSION=v1.6.0`, build halted on `go: /src/go.mod requires go >= 1.27.1 (running go 1.24.13)`. |
| **ModSecurity 3** | `engines/ModSecurity-3-master` | C++17, Autotools | Blocked | Pristine downloaded archive lacks git submodule directories (`others/libinjection` is an empty folder). `./configure` stopped with: `libInjection was not found within ModSecurity source directory. Run: git submodule update --init --recursive`. |
| **Promptfoo** | `engines/promptfoo-main` | Node >= 22.22, TS | In Progress / Heavy Dependencies | `npm install --legacy-peer-deps` in Docker requires hundreds of AI SDK dependencies (Next.js, LangChain, Bedrock). Standalone execution on host verified Node v24.13.0 compatibility. |
| **Wazuh** | `engines/wazuh-main` | C/C++20, Python 3.12 | Blocked on offline source build | Upstream `src/external/` only contains `CMakeLists.txt` and `.gitignore`. Source compilation (`make deps`) requires online CMake `ExternalProject_Add` downloads of OpenSSL, cURL, SQLite, and cJSON tarballs. |

---

## 8. Exact Reproducible Commands

### Run SENTRIX Core Unit & Integration Tests:
```powershell
docker run --rm -v "${PWD}/core:/src" -w /src golang:1.24-alpine go test -v ./tests/...
```

### Build SENTRIX Core Binaries:
```powershell
docker run --rm -v "${PWD}/core:/src" -v "${PWD}/bin:/bin-out" -w /src golang:1.24-alpine sh -c "CGO_ENABLED=0 go build -ldflags='-w -s' -o /bin-out/sentrixd ./cmd/sentrixd && CGO_ENABLED=0 go build -ldflags='-w -s' -o /bin-out/sentrix-waf ./cmd/sentrix-waf"
```

### Build & Run SENTRIX Core Container:
```powershell
docker build -f deploy/docker/Dockerfile.core -t sentrix-core:latest .
docker run -d --name sentrix-core-runtime -p 9000:9000 --add-host=host.docker.internal:host-gateway -e SENTRIX_BIND_ADDRESS=0.0.0.0 sentrix-core:latest
```

### Run Coraza WAF Proxy:
```powershell
docker build -f deploy/docker/Dockerfile.coraza-waf -t sentrix-waf-coraza:latest .
docker run -d --name sentrix-waf-coraza -p 8088:8080 sentrix-waf-coraza:latest
curl http://localhost:8088/healthz
```

### Run End-to-End Adversarial & Remediation Test Suite:
```powershell
node scripts/test-adversarial-suite.js
```
