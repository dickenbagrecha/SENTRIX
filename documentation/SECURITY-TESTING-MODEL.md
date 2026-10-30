# SENTRIX: Security Testing Model and Product Architecture

**Document Type:** Core Specification & Security Testing Model  
**Platform:** SENTRIX Automated Security Auditing, Adversarial Testing, Vulnerability Assessment, Reporting and Remediation Verification Platform  
**Target Focus:** Authorised Applications (including V-LOOKUP staging environments)  
**Status:** Active Specification  

---

## 1. Executive Product Identity & Operational Boundary

### 1.1 What SENTRIX Is
SENTRIX is an **independent, automated cybersecurity platform** dedicated to:
1. **Security Auditing:** Deep inspection of application architecture, authentication, multi-tenant boundaries, document processing, database layers, and deployment configurations.
2. **Controlled Adversarial Testing:** Automated execution of safe, scope-limited security test suites simulating real-world threat actors.
3. **Vulnerability Assessment & Evidence Collection:** Rigorous identification and cryptographic preservation of vulnerability evidence.
4. **Actionable Developer Reporting:** Generation of comprehensive, reproduction-ready engineering reports for development teams (including the V-LOOKUP team).
5. **Remediation Tracking & Regression Verification:** Continuous tracking of defect lifecycles and automated regression testing to prove vulnerabilities are permanently eliminated without collateral regressions.

### 1.2 What SENTRIX Is Not
- **SENTRIX is NOT part of the V-LOOKUP production application.**
- **SENTRIX does NOT run in production alongside end-user traffic.**
- **SENTRIX does NOT automatically modify target applications, rewrite target databases, or apply automated code patches to external systems.**

### 1.3 Operational Separation & Offline Integrity
- **V-LOOKUP Production Constraint:** V-LOOKUP is an offline-capable, air-gapped or restricted-network application processing sensitive client documents. It must maintain zero external internet dependencies.
- **SENTRIX Operational Model:** SENTRIX operates strictly from an **external vantage point**. It targets explicitly authorised staging, testing, or sandbox deployments of V-LOOKUP.
- **Network Decoupling:** SENTRIX itself may utilise internet connectivity for threat intelligence updates (CrowdSec CAPI feeds), CVE synchronization (Wazuh vulnerability databases), and external model evaluations (Promptfoo providers). **Under no circumstances does SENTRIX introduce internet dependencies or foreign network channels into V-LOOKUP.**

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                          OPERATIONAL BOUNDARY TOPOLOGY                          │
│                                                                                 │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                   SENTRIX AUDITING & TEST PLATFORM                      │   │
│   │             (Independent Test Infrastructure / Dedicated VM)            │   │
│   │                                                                         │   │
│   │   • External Internet Access permitted (Threat Intel, CVEs, Evals)      │   │
│   │   • SENTRIX Core Test Orchestrator                                      │   │
│   │   • 12 Attack Category Runners & Synthetic Test Corpus                  │   │
│   │   • Evidence Locker & Remediation State Machine                         │   │
│   │   • Coraza / CrowdSec / ModSecurity / Promptfoo / Wazuh                 │   │
│   └────────────────────────────────────┬────────────────────────────────────┘   │
│                                        │                                        │
│                 Controlled, Scoped     │ Simulated Attacks &                    │
│                 Authorised Testing     │ Audit Requests Only                    │
│                                        ▼                                        │
│   ┌─────────────────────────────────────────────────────────────────────────┐   │
│   │                     AUTHORISED TARGET APPLICATION                       │   │
│   │                       (e.g., V-LOOKUP Staging)                          │   │
│   │                                                                         │   │
│   │   • Isolated Staging / Test Environment                                 │   │
│   │   • Synthetic / Sanitised Client Documents                              │   │
│   │   • Zero External Network Dependencies Required                         │   │
│   │   • Strictly Offline Architecture Preserved                             │   │
│   └─────────────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Authorisation and Safety Framework

Adversarial testing without strict guardrails introduces unacceptable operational risks. SENTRIX enforces an immutable safety protocol:

### 2.1 Explicit Target Authorisation
Before any test suite executes, the target must satisfy an explicit cryptographic or configuration authorization contract:
- **Authorised Host Whitelist:** Tests only dispatch to explicitly configured IP addresses, hostnames, and ports. Requests attempting to resolve outside approved host boundaries are rejected by SENTRIX Core before touching the network stack.
- **Authorisation Token / Scope File:** A cryptographic signature or configuration flag (`authorization.allowed_target_hash`) must be present in `target.json` affirming owner consent for adversarial testing.
- **Default Staging Constraint:** Tests default strictly to `staging` or `development` environment profiles. Production URLs require multi-factor manual confirmation flags.

### 2.2 Non-Destructive Payload Design
- Payloads in the 12 core attack categories are specifically engineered to prove exploitability **without destroying data**:
  - SQL Injection uses read-only probes (e.g., `UNION SELECT`, time delays, or harmless conditional assertions) rather than destructive statements (`DROP`, `TRUNCATE`, `DELETE`).
  - Command Injection uses harmless reconnaissance indicators (e.g., `whoami`, `echo SENTRIX_PROBE_<UUID>`) rather than destructive system modifications.
  - File Upload testing uploads harmless probe documents containing identifiable canary tokens rather than active worms.
- **Controlled Denial of Service:** DoS testing is strictly rate-limited and algorithmic (evaluating whether regex processing or file decompression yields exponential resource spikes), never uncontrolled volumetric traffic flooding that degrades infrastructure.

### 2.3 Synthetic and Sanitised Document Corpus
- V-LOOKUP processes sensitive client files (financial records, spreadsheets, PDF contracts).
- SENTRIX strictly prohibits the use of real client data in test runs.
- SENTRIX provisions and maintains a **Synthetic Test Corpus** (`tests/corpus/`) consisting of artificially generated spreadsheets, mock tax forms, and synthetic invoices embedded with deterministic canary strings to verify document parsing security, cross-tenant isolation, and data exfiltration.

### 2.4 Immutable Evidence Locker & Audit Trail
- Every dispatched probe, HTTP request, response header, response body snippet, execution timing, and error log is serialized and stored in an immutable, cryptographically hashed evidence locker.
- Evidence packages allow developers to independently reproduce findings with absolute mathematical fidelity.

---

## 3. The Twelve Core Attack Categories

SENTRIX Core implements dedicated test scenarios covering the full spectrum of modern enterprise application risks:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                       THE TWELVE CORE ATTACK CATEGORIES                         │
├────┬─────────────────────────────┬─────────────────────────────────────────────┤
│ #  │ Attack Category             │ Scope & V-LOOKUP Specific Vulnerability Focus │
├────┼─────────────────────────────┼─────────────────────────────────────────────┤
│ 1  │ SQL Injection               │ Data queries, filter params, search vectors │
│ 2  │ Cross-Site Scripting (XSS)  │ Rendered document output, web dashboard UI  │
│ 3  │ Broken Authentication       │ Session tokens, password reset, JWT handling│
│ 4  │ Broken Access Control / IDOR│ Direct object ID manipulation across routes │
│ 5  │ Cross-Tenant Data Leakage   │ Multi-tenant document & vector search leaks │
│ 6  │ Prompt Injection            │ Direct/indirect LLM override & jailbreaking │
│ 7  │ RAG Poisoning               │ Adversarial document context & chunk gaming │
│ 8  │ Sensitive Data Exfiltration │ PII/secret leaks via output or error msgs   │
│ 9  │ API Abuse                   │ Rate-limit bypass, mass assignment, replay  │
│ 10 │ Malicious File Upload       │ Zip-bombs, polyglots, parser exploits (XXE) │
│ 11 │ SSRF                        │ Webhooks, document remote URL fetchers      │
│ 12 │ Controlled Denial of Service│ ReDoS, quadratic XML, large PDF compression │
└────┴─────────────────────────────┴─────────────────────────────────────────────┘
```

### Detailed Attack Specifications

#### 1. SQL Injection (SQLi)
- **Vectors:** In-band, blind boolean, and time-based SQL injection across API query filters, pagination parameters, and report generation endpoints.
- **Test Methodology:** Inject benign boundary-breaking strings (`' OR '1'='1`, `SLEEP(2)`) and observe differential response times, error codes, and reflected schemas.
- **Engine Correlation:** Coraza and ModSecurity rules inspect whether the target WAF detects the probe; SENTRIX Core verifies if the backend database leaks data in the absence or bypass of WAF rules.

#### 2. Cross-Site Scripting (XSS)
- **Vectors:** Stored and reflected XSS within document metadata, spreadsheet cell values, and web dashboard rendering views.
- **Test Methodology:** Inject polyglot script payloads (`<svg/onload=alert('SENTRIX_CANARY')>`) into parsed document fields and check for proper contextual encoding in responses.

#### 3. Broken Authentication
- **Vectors:** Credential stuffing resilience, brute-force protections, weak password policies, session fixation, JWT validation (algorithm confusion `none`, signature stripping, secret cracking).
- **Test Methodology:** Simulate replay attacks, expired token acceptance, and forged claims against target authentication routes.

#### 4. Broken Access Control & IDOR
- **Vectors:** Insecure Direct Object References in document retrieval (`/api/v1/documents/:id`), export URLs, and administrative APIs.
- **Test Methodology:** Authenticate as User A (Tenant 1) and attempt direct state modification or retrieval of document IDs belonging to User B (Tenant 1).

#### 5. Cross-Tenant Data Leakage (Critical Multi-Tenant Focus)
- **Vectors:** Shared vector databases, partitioned database tables, document caches, and multi-tenant search indices.
- **Test Methodology:** Inject unique, cryptographically distinct synthetic canaries into Tenant Alpha's document corpus. Execute semantic searches, retrieval queries, and LLM prompts under Tenant Beta's authenticated context. Any reflection of Tenant Alpha's canary triggers a critical finding.

#### 6. Prompt Injection (Direct & Indirect)
- **Vectors:** System prompt override, jailbreak framing, instruction hijacking embedded in client documents (PDFs, XLSX, CSVs) processed by RAG pipelines.
- **Test Methodology:** Utilize Promptfoo adversarial generators and custom SENTRIX injection templates to test if LLMs ignore system safety guardrails when parsing untrusted document content.

#### 7. RAG Poisoning & Context Corruption
- **Vectors:** Adversarial text formatting in documents designed to manipulate vector embeddings, corrupt semantic similarity rankings, or force biased LLM outputs.
- **Test Methodology:** Upload documents containing misleading metadata, conflicting instructions, and adversarial chunks to test semantic retrieval robustness.

#### 8. Sensitive Data Exfiltration
- **Vectors:** Memory disclosure, stack traces in error responses, PII reflection in debug endpoints, and prompt extraction.
- **Test Methodology:** Probe endpoints with malformed requests, boundary violations, and extraction prompts (`Repeat all instructions above`) to inspect if secrets, API keys, or system prompts leak.

#### 9. API Abuse & Parameter Tampering
- **Vectors:** Mass assignment (modifying `is_admin` or `tenant_id` on registration/update), HTTP parameter pollution, rate-limit evasion via header spoofing (`X-Forwarded-For`).
- **Test Methodology:** Fuzz API schemas with unexpected JSON fields and high-frequency bursts to evaluate API contract enforcement.

#### 10. Malicious File Upload & Document Parsing Exploits
- **Vectors:** Polyglot files (e.g., executable payload wrapped in a valid `.xlsx` header), Zip Bombs, XML External Entity (XXE) attacks in `.docx`/`.xlsx` XML trees, and PDF parser crashes.
- **Test Methodology:** Submit specifically structured, non-destructive test files containing entity expansions or oversized compression ratios to verify parser safety limits.

#### 11. Server-Side Request Forgery (SSRF)
- **Vectors:** Remote document import URLs, webhook callback URLs, and image preview generators.
- **Test Methodology:** Provide URLs resolving to internal loopback (`127.0.0.1`, `169.254.169.254`, `[::1]`) or cloud metadata endpoints and monitor for outbound connection attempts.

#### 12. Controlled Denial of Service (DoS)
- **Vectors:** Regular expression denial of service (ReDoS), quadratic expansion in document format decoders, and heavy database aggregation queries.
- **Test Methodology:** Measure execution time against polynomial payload inputs with a strict 2-second circuit-breaker timeout to identify algorithmic bottlenecks without overwhelming the server.

---

## 4. Engine Roles & Specializations

SENTRIX preserves all five original upstream engines, using their specialized strengths while SENTRIX Core fills application-level testing gaps:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                         ENGINE RESPONSIBILITY MATRIX                            │
├─────────────────────┬───────────────────────────────────────────────────────────┤
│ Engine              │ Specific Responsibility in SENTRIX Testing Ecosystem      │
├─────────────────────┼───────────────────────────────────────────────────────────┤
│ **OWASP Coraza**    │ WAF rule validation, HTTP attack payload filtering,       │
│                     │ SecLang evasion testing, and CRS v4 inspection benchmark  │
├─────────────────────┼───────────────────────────────────────────────────────────┤
│ **CrowdSec**        │ Behavioral profiling, brute-force / crawling detection,   │
│                     │ IP threat intelligence, and rate-limiting audit           │
├─────────────────────┼───────────────────────────────────────────────────────────┤
│ **ModSecurity 3**   │ Independent C++ WAF reference baseline, verifying rule   │
│                     │ parity and connector behavior against Coraza              │
├─────────────────────┼───────────────────────────────────────────────────────────┤
│ **Promptfoo**       │ LLM adversarial red-teaming, prompt injection synthesis,  │
│                     │ RAG hallucination evaluation, and safety guardrail checks │
├─────────────────────┼───────────────────────────────────────────────────────────┤
│ **Wazuh 5.1**       │ Host integrity monitoring (FIM), system audit logs,       │
│                     │ OS-level anomalies, CVE matching, and SIEM correlation    │
├─────────────────────┼───────────────────────────────────────────────────────────┤
│ **SENTRIX Core**    │ Test runner orchestration, target authorization & scope,  │
│                     │ multi-tenant audit, 12-category test logic, evidence      │
│                     │ capture, developer reporting, and regression tracking     │
└─────────────────────┴───────────────────────────────────────────────────────────┘
```

> [!IMPORTANT]
> **No Magic Bullet:** The five upstream engines do not natively understand V-LOOKUP's specific multi-tenant database models or document processing workflows. **SENTRIX Core provides the application-aware test logic**, while the engines provide specialized detection, verification, and telemetry services.

---

## 5. Vulnerability Findings & Evidence Model

When a test scenario successfully exposes a weakness, SENTRIX Core constructs a formal, immutable **Vulnerability Finding Record**:

### Finding Schema Attributes
- **Finding ID:** Unique UUID (`finding_id`).
- **Category:** One of the 12 Core Attack Categories.
- **Title:** Precise description (e.g., `Unrestricted IDOR in Document Download Endpoint`).
- **Target Endpoint:** Method and path (e.g., `GET /api/v1/documents/{document_id}/download`).
- **Affected Component:** Subsystem (e.g., `DocumentManager`, `RAGPipeline`, `AuthService`).
- **Severity:** `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL` (CVSS v3.1 aligned).
- **Confidence:** `CONFIRMED` (proven exploit), `HIGH` (strong indicator), `SUSPECTED` (anomaly).
- **Technical Evidence:**
  - Full HTTP request (headers, body, method, path).
  - Full HTTP response (status code, response headers, response body snippet).
  - Canary token reflection or timing measurements.
  - Log correlation from Wazuh/Coraza/CrowdSec.
- **Reproduction Instructions:** Standalone, copy-pasteable `curl` command or automated test script.
- **Business & Security Impact:** Real-world consequence if exploited in production (e.g., unauthorized access to competitor financial spreadsheets).
- **Remediation Recommendation:** Explicit code-level architectural advice for developers.
- **Regression Test ID:** Identifier of the automated test scenario used to verify the fix.

---

## 6. Actionable Developer Reporting

SENTRIX generates structured reports specifically tailored to developers and security leads.

### Developer Report Template Example

```markdown
# [VULN-2026-0042] Cross-Tenant Document Access via IDOR

- **Category:** Cross-Tenant Data Leakage / Broken Access Control
- **Severity:** CRITICAL (CVSS: 9.1)
- **Status:** Reported
- **Assigned Developer:** unassigned
- **Affected Endpoint:** `GET /api/v1/tenants/{tenant_id}/documents/{document_id}`
- **Affected Component:** `StorageService::getDocumentStream`

---

### 1. Vulnerability Summary
The document retrieval endpoint fails to validate whether the authenticated user's tenant ID matches the `tenant_id` route parameter, allowing an authenticated member of Tenant Alpha to access sensitive documents belonging to Tenant Beta by substituting the document UUID.

### 2. Technical Evidence
- **Request Dispatched:**
  ```http
  GET /api/v1/tenants/tenant-beta/documents/doc-994827-confidential HTTP/1.1
  Host: staging.vlookup.local
  Authorization: Bearer <TOKEN_TENANT_ALPHA>
  ```
- **Response Received:**
  ```http
  HTTP/1.1 200 OK
  Content-Type: application/vnd.openxmlformats-officedocument.spreadsheetml.sheet
  X-Tenant-Owner: tenant-beta
  
  [Binary Spreadsheet Payload: Q3 Financial Audit]
  ```
- **Canary Match:** Synthetic canary `CANARY_TENANT_BETA_994827` reflected in output stream.

### 3. Step-by-Step Reproduction
Execute the following cURL command against the staging environment:
```bash
curl -X GET "http://staging.vlookup.local/api/v1/tenants/tenant-beta/documents/doc-994827-confidential" \
     -H "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." \
     -o output.xlsx
```

### 4. Business & Security Impact
An attacker with a standard low-privilege account in any tenant organization can enumerate and exfiltrate proprietary spreadsheets, financials, and employee records of all other organizations hosted on the platform.

### 5. Recommended Remediation
1. Enforce tenant boundary checks in the repository query layer:
   ```go
   // Ensure queries bind both document_id AND the caller's tenant_id from claims
   query := "SELECT * FROM documents WHERE id = ? AND tenant_id = ?"
   ```
2. Reject requests where the URL `tenant_id` does not match `claims.TenantID` with `403 Forbidden`.

### 6. Automated Regression Test Command
```bash
sentrixctl test --category cross-tenant-leakage --target staging.vlookup.local --finding VULN-2026-0042
```
```

---

## 7. Remediation Tracking & Regression Lifecycle

SENTRIX treats vulnerability management as a deterministic state machine:

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                        REMEDIATION LIFECYCLE STATES                             │
│                                                                                 │
│   ┌───────────┐        ┌───────────┐        ┌───────────┐                       │
│   │ Detected  ├───────►│ Confirmed ├───────►│ Reported  │                       │
│   └───────────┘        └───────────┘        └─────┬─────┘                       │
│                                                   │                             │
│                                                   ▼                             │
│   ┌───────────┐        ┌───────────┐        ┌───────────┐                       │
│   │   Fixed   │◄───────┤In Progress│◄───────┤ Assigned  │                       │
│   └─────┬─────┘        └───────────┘        └───────────┘                       │
│         │                                                                       │
│         ▼                                                                       │
│   ┌───────────┐       Failed Regression       ┌───────────┐                     │
│   │ Retesting ├──────────────────────────────►│In Progress│                     │
│   └─────┬─────┘                               └───────────┘                     │
│         │                                                                       │
│         │ Passed Regression                                                     │
│         ▼                                                                       │
│   ┌───────────┐                             ┌───────────┐                       │
│   │ Verified  ├────────────────────────────►│  Closed   │                       │
│   └───────────┘                             └───────────┘                       │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### State Definitions
1. **`Detected`:** An anomaly or security alert was flagged by a test scenario or engine.
2. **`Confirmed`:** SENTRIX Core verified the vulnerability with a reproducible exploit proof.
3. **`Reported`:** Formal report generated and delivered to the development team.
4. **`Assigned`:** A developer has been assigned to address the finding.
5. **`Fix In Progress`:** Development team is actively modifying code.
6. **`Fixed`:** Developer marks the finding as resolved and requests verification.
7. **`Retesting`:** SENTRIX regression engine automatically reruns the exact test scenario against the updated staging build.
8. **`Verified`:** Regression test confirms the original exploit is completely mitigated and related tests pass.
9. **`Closed`:** Issue is archived with a signed verification report.

---

## 8. Automated Regression Testing Engine

When a developer submits a fix, SENTRIX executes a two-phase **Regression Verification Routine**:

1. **Targeted Reproduction Check:**
   - Re-executes the exact original attack vector with identical parameters.
   - Verifies that the vulnerability no longer triggers (e.g., returns `403 Forbidden` or `404 Not Found` instead of leaking data).
2. **Boundary & Collateral Regression Scan:**
   - Executes surrounding attack scenarios within the same category to ensure the fix did not introduce side-effects.
   - For example, if an SQLi fix was implemented via input sanitation, verifies that valid document searches and legitimate special characters continue functioning normally.

---

*End of Security Testing Model Specification.*
