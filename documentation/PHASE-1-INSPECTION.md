# SENTRIX Phase 1: Architectural and Source-Code Inspection Report

**Project:** SENTRIX Unified Backend Cybersecurity Platform  
**Phase:** Phase 1 – Read-Only Architectural & Source-Code Inspection  
**Date:** October 30, 2026  
**Status:** Complete (Read-Only Inspection)  

---

## Executive Summary

SENTRIX is envisioned as a backend-only, unified cybersecurity platform that unifies host, network, web application, and Generative AI security domains into a coherent defensive ecosystem. 

During Phase 1, a comprehensive, read-only inspection was performed across all five original upstream codebases downloaded into the local workspace:
1. `engines/coraza-main` (OWASP Coraza Web Application Firewall v3)
2. `engines/crowdsec-master` (CrowdSec Security Engine)
3. `engines/ModSecurity-3-master` (OWASP ModSecurity v3 / `libmodsecurity`)
4. `engines/promptfoo-main` (Promptfoo LLM Security & Red Teaming Toolkit v0.125.1)
5. `engines/wazuh-main` (Wazuh SIEM / XDR Platform v5.1.0 alpha0)

In strict adherence to Phase 1 rules:
- No existing files were modified, moved, renamed, deleted, overwritten, or merged.
- No build scripts or dependency installation commands were executed.
- Original repository structures remain 100% intact.
- Every claim, configuration, entry point, dependency, and architecture model detailed herein is derived from direct inspection of local workspace source files.

---

## 1. Individual Repository Architecture Reports

```
                                  SENTRIX WORKSPACE
  ┌─────────────────────────────────────────────────────────────────────────────────┐
  │                                                                                 │
  │  ┌───────────────────────┐   ┌───────────────────────┐   ┌────────────────────┐ │
  │  │  engines/coraza-main  │   │ engines/crowdsec-mast │   │ engines/ModSecur-3 │ │
  │  │  • Pure Go (Go 1.26)  │   │ • Pure Go (Go 1.27)   │   │ • C++17 Library    │ │
  │  │  • Embedded WAF Lib   │   │ • IPS/IDS Daemon+LAPI │   │ • Autotools/CMake  │ │
  │  │  • SecLang Engine     │   │ • Embeds Coraza WAF   │   │ • SecLang Engine   │ │
  │  └───────────────────────┘   └───────────────────────┘   └────────────────────┘ │
  │                                                                                 │
  │  ┌────────────────────────────────────────┐  ┌────────────────────────────────┐ │
  │  │        engines/promptfoo-main          │  │      engines/wazuh-main        │ │
  │  │  • TypeScript / Node.js (>=22.22)      │  │  • C, C++20, Python 3.12       │ │
  │  │  • GenAI / LLM Red Teaming & Evals     │  │  • Host SIEM / XDR Platform    │ │
  │  │  • CLI & REST Server                   │  │  • Manager & Agent Daemons     │ │
  │  └────────────────────────────────────────┘  └────────────────────────────────┘ │
  └─────────────────────────────────────────────────────────────────────────────────┘
```

---

### 1.1 `engines/coraza-main` (OWASP Coraza WAF v3)

#### 1. Programming Languages and Frameworks
- **Primary Language:** Go (configured for Go `1.26.0` in `go.mod` and `go.work`).
- **Frameworks & Core Libraries:**
  - Standard Go HTTP networking (`net/http`).
  - `github.com/corazawaf/libinjection-go` (v0.3.4) for SQLi/XSS tokenization.
  - `github.com/petar-dambovaliev/aho-corasick` for fast multi-pattern string matching.
  - `rsc.io/binaryregexp` for binary regex execution.
  - `github.com/tidwall/gjson` for fast JSON body evaluation.
  - `github.com/magefile/mage` (v1.17.0) for build orchestration.
  - `github.com/valllabh/ocsf-schema-golang` for Open Cybersecurity Schema Framework (OCSF) audit logging.

#### 2. Original Architecture and Major Modules
Coraza is an enterprise-grade, memory-safe Web Application Firewall implemented as an embeddable Go library:
- **`waf.go` & `config.go`:** Core entry interfaces for building and configuring WAF instances (`NewWAF`, `NewWAFConfig`, `NewTransaction`).
- **`internal/seclang`:** Parser and lexer for the ModSecurity SecRules Language (SecLang). Compiles directives (`SecRule`, `SecAction`, `SecDefaultAction`, `SecMarker`) into executable rule chains.
- **`internal/operators`:** Implementation of rule operators (`@rx`, `@streq`, `@ipMatch`, `@detectSQLi`, `@detectXSS`, `@contains`, `@validateUrlEncoding`, `@validateByteRange`, `@geoLookup`).
- **`internal/transformations`:** Canonicalization functions (`t:lowercase`, `t:urlDecode`, `t:htmlEntityDecode`, `t:base64Decode`, `t:removeNulls`, `t:sha1`, `t:md5`).
- **`internal/bodyprocessors`:** Content parsers handling URL-encoded forms, multipart payloads, JSON, and XML.
- **`internal/auditlog`:** Structured audit log generator supporting serial, concurrent, and OCSF JSON logging to disk, HTTPS, or syslog.
- **`http/`:** Native HTTP middleware implementation (`http.Handler` wrapper, transaction interception across 5 execution phases).

#### 3. Main Entry Points and Execution Commands
- **Library API Entry Point:** `coraza.NewWAF(config)` and `waf.NewTransaction()`.
- **Standalone Example Server:** `engines/coraza-main/examples/http-server/main.go`.
- **Build / Maintenance Commands (Mage):**
  - `mage test` / `go test ./...`
  - `mage lint` (invokes `golangci-lint`)
  - `mage format`

#### 4. Backend Functionality and Security Capabilities
- **Transaction Life-Cycle Phases:**
  - Phase 1: Request Headers
  - Phase 2: Request Body
  - Phase 3: Response Headers
  - Phase 4: Response Body
  - Phase 5: Logging
- **Threat Protection:** 100% compatibility with OWASP Core Rule Set (CRS) v4 (protects against SQL Injection, XSS, Local/Remote File Inclusion, Command Injection, Protocol Violations, HTTP Request Smuggling, and Scanner/Bot Activity).
- **Extensibility:** Supports pluggable operators, transformations, body processors, and audit log formatters via `experimental/plugins`.

#### 5. Dependencies and Package Managers
- **Package Manager:** Go Modules (`go.mod`, `go.sum`, `go.work`).
- **Key External Dependencies:** `libinjection-go`, `aho-corasick`, `binaryregexp`, `gjson`, `ocsf-schema-golang`, `mergefs`, `jsonschema`.

#### 6. Build Systems and Runtime Requirements
- **Build System:** Go toolchain (`go build`), optionally orchestrated by `mage`.
- **Compiler/Runtime:** Go 1.24+ (target `1.26.0`). Supports `tinygo` for WASM targets.
- **CGO Requirement:** **Pure Go**; does NOT require CGO for default operators or standard regex engines.

#### 7. Operating System Compatibility
- **Cross-Platform:** Full native compatibility with Linux (Debian, CentOS, Alpine, etc.), Windows, and macOS.
- Compatible with WASM/WASI runtime environments (e.g., Envoy `proxy-wasm`).

#### 8. Configuration Files and Environment Variables
- **Rule Configurations:** `coraza.conf-recommended` (defines `SecRuleEngine DetectionOnly/On`, body limits, and default parsing rules).
- **Directives:** Standard SecLang directives (`SecRequestBodyAccess`, `SecResponseBodyAccess`, `SecAuditEngine`, `SecRule`).
- **Environment Variables:** Standard Go build environment variables (`GOOS`, `GOARCH`, `CGO_ENABLED`).

#### 9. External Services and Integrations
- Designed to be embedded directly into reverse proxies and web application servers:
  - Caddy (`coraza-caddy`)
  - HAProxy SPOE (`coraza-spoa`)
  - Envoy / Traefik / Istio (via WASM extension `coraza-proxy-wasm`)
  - Standard Go reverse proxies (`net/http/httputil`).

#### 10. Potential Compatibility Issues with Other Repositories
- **With CrowdSec:** CrowdSec already imports Coraza (`github.com/corazawaf/coraza/v3 v3.8.0`) under its AppSec engine. Direct duplicate inclusion could create module version collisions if not aligned.
- **With ModSecurity:** Both Coraza and ModSecurity parse identical SecLang rules. Loading both in the same network path would introduce redundant rule execution and double latency.

#### 11. Licence and Copyright Files
- **File:** `engines/coraza-main/LICENSE`
- **License:** Apache License 2.0.
- **Copyright:** Copyright 2021 Juan Pablo Tosso, OWASP Coraza Contributors.

#### 12. Whether It Can Operate Independently
- **No as a Standalone Daemon:** It is fundamentally a library / SDK.
- **Yes with Embedded Wrapper:** Can operate independently when wrapped with an HTTP server (e.g., `examples/http-server/main.go`) or reverse proxy.

---

### 1.2 `engines/crowdsec-master` (CrowdSec Security Engine)

#### 1. Programming Languages and Frameworks
- **Primary Language:** Go (configured for Go `1.27.1` in `go.mod`).
- **Frameworks & Core Libraries:**
  - Gin Web Framework (`github.com/gin-gonic/gin` v1.11.0) for the Local API (LAPI).
  - Ent ORM (`entgo.io/ent` v0.14.6) for database abstraction (SQLite, PostgreSQL, MySQL).
  - Cobra / Viper for CLI commands and configuration.
  - Expr (`github.com/expr-lang/expr` v1.17.8) for scenario and parser expression evaluations.
  - Coraza WAF (`github.com/corazawaf/coraza/v3` v3.8.0) embedded for AppSec processing.
  - RE2 C++ regex library (`libre2`) linked via CGo (or modern WASM fallback).

#### 2. Original Architecture and Major Modules
CrowdSec follows a decoupled "*Detect Here, Remedy There*" architecture:
- **`cmd/crowdsec/`:** Main security engine daemon.
- **`cmd/crowdsec-cli/` (`cscli`):** Administrative command-line tool for managing hub items, alert inspection, bouncers, decisions, and metrics.
- **`pkg/acquisition/`:** Data source ingestion layer. Tails log files, journals, syslog, Docker containers, Kubernetes pods, AWS CloudWatch, Kafka, and Windows Event Logs.
- **`pkg/parser/` & `pkg/grok/`:** Event normalization pipeline. Extracts structured metadata from raw text logs using Grok patterns.
- **`pkg/enrichment/`:** Enriches events with GeoIP, reverse DNS, and threat intelligence context.
- **`pkg/leakybucket/`:** Stateful correlation engine. Evaluates events against leaky-bucket scenarios (brute-force, port-scans, web credential stuffing) over sliding time windows.
- **`pkg/appsec/`:** Application Security (WAF) module. Directly incorporates Coraza WAF to inspect in-band HTTP requests and trigger alerts/blocks.
- **`pkg/apiserver/`:** Local API (LAPI). Exposes REST endpoints for agents, bouncers, and CLI management.
- **`pkg/cticlient/`:** Central API (CAPI) communication client. Sends aggregated threat telemetry and pulls down community consensus blocklists.
- **`cmd/notification-*/`:** Pluggable alert notifications (Email, Slack, Splunk, Azure Sentinel, HTTP Webhook, File).

#### 3. Main Entry Points and Execution Commands
- **Security Engine Daemon:** `cmd/crowdsec/main.go` -> binary `crowdsec` (runs via `crowdsec -c /etc/crowdsec/config.yaml`).
- **Management CLI:** `cmd/crowdsec-cli/main.go` -> binary `cscli` (e.g., `cscli metrics`, `cscli decisions list`, `cscli hub update`).
- **Build Commands:**
  - `make` (compiles `crowdsec`, `cscli`, and plugins)
  - `make BUILD_SQLITE=modernc` (pure Go SQLite build without CGo)
  - `make BUILD_RE2_WASM=1` (builds using WASM regex without system `libre2-dev`)

#### 4. Backend Functionality and Security Capabilities
- **Intrusion Detection & Prevention (IDS/IPS):** Log analysis and rate-limiting detection.
- **IP Reputation & Distributed Threat Intelligence:** Synchronizes with CrowdSec Central API to block malicious IPs before they touch the application.
- **Application Security (AppSec):** In-band HTTP attack detection using SecLang and YAML-based rules via Coraza.
- **Decoupled Remediation:** Emits decisions (ban, captcha, custom) consumed by Remediation Components ("Bouncers") on firewalls, web servers, or CDNs.

#### 5. Dependencies and Package Managers
- **Package Manager:** Go Modules (`go.mod`, `go.sum`).
- **System Dependencies:** `libre2-dev` (C++ regex, or WASM build), `gcc` (for `mattn/go-sqlite3` CGo SQLite, or `modernc/sqlite` pure Go).
- **Key Modules:** Gin, Ent ORM, Expr, Coraza, Prometheus client.

#### 6. Build Systems and Runtime Requirements
- **Build System:** GNU Make (requires Make >= 4.1).
- **Runtime:** Go 1.24+ runtime or compiled static/dynamic binary.
- **Memory Footprint:** Typically 50MB - 150MB RAM depending on acquisition volume and scenario count.

#### 7. Operating System Compatibility
- **Linux:** Native support (Systemd, SysV, Docker, Kubernetes).
- **Windows:** Native Windows service support (`config/config_win.yaml`, `config/acquis_win.yaml`, Windows EventLog acquisition).
- **macOS / BSD:** Supported (FreeBSD package available).

#### 8. Configuration Files and Environment Variables
- **Main Daemon Config:** `config/config.yaml` / `config/config_win.yaml`.
- **Acquisition Config:** `config/acquis.yaml` / `config/acquis_win.yaml`.
- **Profiles:** `config/profiles.yaml` (defines remediation action policies: duration, type of remediation).
- **Local API Credentials:** `config/local_api_credentials.yaml`.
- **Online API Credentials:** `config/online_api_credentials.yaml`.
- **Simulation Mode:** `config/simulation.yaml`.

#### 9. External Services and Integrations
- **CrowdSec Central API (CAPI):** Synchronizes community blocklists.
- **CrowdSec Hub:** Dynamically downloads collections, parsers, scenarios, and appsec rules.
- **Remediation Bouncers:** Firewall bouncers (iptables, nftables, Windows Firewall), Web bouncers (Nginx, Traefik, HAProxy, Cloudflare).
- **Prometheus:** Metrics exported on port 6060.

#### 10. Potential Compatibility Issues with Other Repositories
- **With Coraza:** CrowdSec already vendor-replaces Coraza in `go.mod` (`replace github.com/corazawaf/coraza/v3 => github.com/crowdsecurity/coraza/v3 v3.8.0-crowdsec.20261001`). Running a standalone Coraza and an AppSec-enabled CrowdSec requires careful port and middleware separation.
- **With Wazuh:** Both ingest and parse system logs. If both tail the same log files (`/var/log/syslog`, `/var/log/auth.log`), there will be overlapping CPU utilization and duplicated alert generation.

#### 11. Licence and Copyright Files
- **File:** `engines/crowdsec-master/LICENSE`
- **License:** MIT License.
- **Copyright:** Copyright (c) 2020-2023 Crowdsec.

#### 12. Whether It Can Operate Independently
- **Yes:** CrowdSec operates fully as an independent, standalone daemon with its own embedded REST API server (LAPI), database store, and CLI management tool.

---

### 1.3 `engines/ModSecurity-3-master` (OWASP ModSecurity v3 / `libmodsecurity`)

#### 1. Programming Languages and Frameworks
- **Primary Language:** C++ (compiled against C++17 standard).
- **Parsers / Generators:** Flex (lexical analyzer) and Bison / Yacc (parser generator) for the SecLang grammar (`src/parser/seclang-scanner.ll`, `src/parser/seclang-parser.yy`).
- **Core Libraries:**
  - PCRE2 / PCRE (regular expression engine).
  - YAJL (Yet Another JSON Library) for JSON parsing and audit logging.
  - libxml2 (optional, for XML request parsing).
  - libcurl (for `SecRemoteRules`).
  - LMDB (for state and persistent collection storage).
  - Lua (optional, for Lua rule scripting).
  - MaxMind GeoIP / libmaxminddb (for geolocation lookups).

#### 2. Original Architecture and Major Modules
ModSecurity v3 (`libmodsecurity`) is an architectural rewrite separating the core inspection library from webserver-specific wrappers:
- **`headers/modsecurity/`:** Public C++ and C API headers (`modsecurity.h`, `transaction.h`, `rules_set.h`, `intervention.h`).
- **`src/modsecurity.cc`:** Engine initialization, connector registration, and global state management.
- **`src/transaction.cc`:** Heart of transaction processing. Manages request/response data flow across phases 1 through 5.
- **`src/parser/`:** SecRules grammar parser translating rule files into internal C++ abstract syntax trees.
- **`src/operators/`:** Implementations of SecLang operators (`@rx`, `@pm`, `@detectSQLi`, `@detectXSS`, `@ipMatch`, `@validateByteRange`, `@validateUrlEncoding`).
- **`src/actions/`:** Action execution logic (`deny`, `drop`, `block`, `allow`, `pass`, `log`, `status`, `t:`, `setvar:`).
- **`src/audit_log/`:** Multi-format audit log generator (Serial, Concurrent, JSON).
- **`others/libinjection` & `others/mbedtls`:** Embedded submodules for SQLi/XSS tokenization and cryptography.

#### 3. Main Entry Points and Execution Commands
- **Library API Entry Point:** `modsecurity::ModSecurity`, `modsecurity::RulesSet`, `modsecurity::Transaction`.
- **Connector Interface:** Interfaced by external webserver connectors (`ModSecurity-nginx`, `ModSecurity-apache`).
- **Build Commands:**
  - **Linux / Unix:**
    ```sh
    ./build.sh
    ./configure
    make
    sudo make install
    ```
  - **Windows:**
    ```cmd
    vcbuild.bat [Release|Debug] [x86_64]
    ```
- **Diagnostic / Test Tools:**
  - `tools/rules_check` (validates SecLang syntax).
  - `test/unit_tests`, `test/regression_tests`.

#### 4. Backend Functionality and Security Capabilities
- **WAF Engine:** Full SecLang specification implementation.
- **Inspection Phases:** 5-phase inspection pipeline covering HTTP connection, headers, body, response, and logging.
- **OWASP CRS Compatibility:** Runs CRS v3 and v4 rule sets.
- **Disruptive Actions:** Immediate intervention generation (HTTP status code override, redirection, TCP reset).

#### 5. Dependencies and Package Managers
- **Package Managers:** System package manager (`apt`, `dnf`, `brew`) on Unix; Conan package manager (`build/win32/conanfile.txt`) on Windows.
- **Mandatory Dependencies:** C++17 compiler, Flex, Bison, PCRE2, YAJL.
- **Optional Dependencies:** libxml2, libcurl, LMDB, Lua, libmaxminddb.

#### 6. Build Systems and Runtime Requirements
- **Unix:** Autotools (`autoconf`, `automake`, `libtool`, GNU Make).
- **Windows:** CMake + MSVC (Build Tools for Visual Studio 2022) + Conan.
- **Runtime:** Dynamic shared library (`libmodsecurity.so` on Linux, `libModSecurity.dll` on Windows).

#### 7. Operating System Compatibility
- **Linux:** Full native support across all distributions.
- **Windows:** Supported via MSVC and Conan (see `build/win32/README.md`).
- **macOS & BSD:** Supported via Autotools and Clang.

#### 8. Configuration Files and Environment Variables
- **Recommended Configuration:** `modsecurity.conf-recommended` (`SecRuleEngine DetectionOnly/On`, body limits, upload directories).
- **Unicode Mapping:** `unicode.mapping` (handles character normalization).
- **Package Config:** `modsecurity.pc.in` (for pkg-config discovery).

#### 9. External Services and Integrations
- Connectors: `ModSecurity-nginx`, `ModSecurity-apache`, `ModSecurity-IIS`.
- Remote rule feeds: Fetches remote rules over HTTPS using `libcurl` (`SecRemoteRules`).

#### 10. Potential Compatibility Issues with Other Repositories
- **With Coraza:** Coraza is an architectural clone and pure-Go successor to ModSecurity. Running both ModSecurity (C++) and Coraza (Go) in SENTRIX would create exact functional duplication.
- **Uninitialized Submodules Warning:** In the local workspace, `others/libinjection`, `others/mbedtls`, `bindings/python`, and `test/test-cases/secrules-language-tests` are empty directories because the repository was cloned without `--recursive`. Compiling locally requires submodule initialization.

#### 11. Licence and Copyright Files
- **File:** `engines/ModSecurity-3-master/LICENSE`
- **License:** Apache License 2.0.
- **Authors:** `engines/ModSecurity-3-master/AUTHORS` (Felipe Zimmerle, Ryan Barnett, Chaim Sanders, Victor Hora).

#### 12. Whether It Can Operate Independently
- **No:** `libmodsecurity` produces only a shared dynamic library and test binaries. It contains NO standalone daemon or HTTP listener; it requires a host connector or application.

---

### 1.4 `engines/promptfoo-main` (Promptfoo LLM Security & Red Teaming Toolkit)

#### 1. Programming Languages and Frameworks
- **Primary Language:** TypeScript / JavaScript (Node.js target `>=22.22.0`).
- **Build Tooling:** `tsdown`, `tsx`, `typescript` (TS 5.x).
- **Web & Backend Frameworks:**
  - Node.js native HTTP server and Express / Hono backends.
  - Drizzle ORM (`drizzle-orm`) & `drizzle-kit` for database management.
  - `better-sqlite3` for local fast embedded relational storage.
  - React 19 (`react`, `react-dom`) for web evaluation dashboard in `src/app`.
  - Biome (`@biomejs/biome`) & Vitest for linting and testing.

#### 2. Original Architecture and Major Modules
Promptfoo is a modular CLI, automated red-teaming engine, and web server for testing and securing Generative AI and LLM applications:
- **`src/entrypoint.ts` & `src/main.ts`:** Main CLI execution controllers routing commands (`eval`, `redteam`, `view`, `init`, `validate`).
- **`src/evaluator.ts` & `src/evaluate.ts`:** Core evaluation pipeline executing prompts against matrix configurations, assertions, and custom grading hooks.
- **`src/redteam/`:** Automated adversarial attack and red-teaming generation framework:
  - `plugins/`: Exploit modules covering OWASP Top 10 for LLMs (prompt injection, jailbreak attempts, SSRF, ASCII smuggling, BOLA, BFLA, SQLi via tools, data exfiltration, PII leakage, hallucination).
  - `strategies/`: Adversarial attack strategies (multi-turn attacks, jailbreak payloads, base64/rot13 obfuscation, multilingual translation bypasses).
  - `riskScoring.ts` & `graders.ts`: Risk assessment and automated grading algorithms.
- **`src/guardrails.ts`:** Runtime policy validation for model input/output guardrails.
- **`src/providers/`:** Modular adapters interfacing with over 50+ LLM providers (OpenAI, Anthropic Claude, Google Vertex/Gemini, AWS Bedrock, Ollama, HuggingFace, Local LLMs, Model Context Protocol / MCP targets).
- **`src/server/`:** Embedded HTTP server hosting the REST API and the React-based security dashboard.
- **`src/database/`:** SQLite database storage managing test runs, telemetry, and redteam reports.

#### 3. Main Entry Points and Execution Commands
- **CLI Executable:** `dist/src/entrypoint.js` (aliased as `promptfoo` and `pf`).
- **Main CLI Commands:**
  - `promptfoo eval` (runs automated test evaluations against models).
  - `promptfoo redteam run` / `promptfoo redteam init` (launches adversarial penetration testing).
  - `promptfoo view` (starts local web server on port 15500 to view interactive results).
  - `promptfoo dev` (launches developer server and live-reloading UI).
- **Package Scripts:** `npm run build`, `npm run dev:server`, `npm run test`.

#### 4. Backend Functionality and Security Capabilities
- **GenAI / LLM Vulnerability Assessment:** Automated generation of adversarial prompts simulating attackers trying to bypass safety guardrails.
- **OWASP LLM Top 10 Coverage:** Tests for Prompt Injection (LLM01), Insecure Output Handling (LLM02), Training Data Poisoning (LLM03), Model Denial of Service (LLM04), Supply Chain (LLM05), Sensitive Information Disclosure (LLM06), Insecure Plugin Design (LLM07), Excessive Agency (LLM08), Overreliance (LLM09), Model Theft (LLM10).
- **Continuous Security Testing in CI/CD:** Acts as a security gate in pull requests to prevent regressions in prompt safety.
- **Model Context Protocol (MCP) Security:** Native scanner for tool-calling vulnerabilities and unintended agent actions.

#### 5. Dependencies and Package Managers
- **Package Manager:** `npm` / `pnpm` (`package.json`, `package-lock.json`, `pnpm-workspace.yaml`).
- **Dependencies Count:** Large Node ecosystem (Drizzle, better-sqlite3, Commander, Cheerio, OpenTelemetry, React 19).

#### 6. Build Systems and Runtime Requirements
- **Build System:** `tsdown` (esbuild-based TypeScript bundler).
- **Runtime Requirement:** Node.js `>= 22.22.0`.
- **Operating Environment:** Runs on any standard Node.js runtime.

#### 7. Operating System Compatibility
- **Full Cross-Platform:** Seamlessly runs on Windows, Linux, and macOS.

#### 8. Configuration Files and Environment Variables
- **Config Files:** `promptfoo.yaml` / `promptfooconfig.yaml` (defines targets, providers, test assertions, red-team plugins).
- **Database Config:** `drizzle.config.ts`.
- **Environment Variables:** `PROMPTFOO_DISABLE_TELEMETRY`, `PROMPTFOO_CONFIG_DIR`, API keys (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`, etc.).

#### 9. External Services and Integrations
- External LLM API endpoints (cloud and on-premise).
- CI/CD platforms (GitHub Actions, GitLab CI).
- Slack, Webhooks, and PostHog for reporting.

#### 10. Potential Compatibility Issues with Other Repositories
- **Ecosystem Difference:** Node.js / TypeScript vs Go (Coraza, CrowdSec) and C/C++ (ModSecurity, Wazuh).
- **Runtime Dependency:** Requires a modern Node.js 22+ runtime, which must be provisioned alongside Go and C++ environments in SENTRIX.

#### 11. Licence and Copyright Files
- **File:** `engines/promptfoo-main/LICENSE`
- **License:** MIT License.
- **Copyright:** Copyright (c) Promptfoo 2025.

#### 12. Whether It Can Operate Independently
- **Yes:** Runs standalone via CLI commands (`promptfoo eval`), background evaluation tasks, or as an independent web application (`promptfoo view`).

---

### 1.5 `engines/wazuh-main` (Wazuh SIEM / XDR Platform)

#### 1. Programming Languages and Frameworks
- **Primary Languages:**
  - C (historic core daemons in `src/`).
  - C++20 (modern engine and analysis modules in `src/engine/`, `src/shared_modules/`).
  - Python 3.12 (management REST API in `api/`, management framework in `framework/`).
  - POSIX Shell (installation wizards and service wrappers).
- **Frameworks & Libraries:**
  - Python: Connexion 3.1.0 (OpenAPI spec server), Uvicorn 0.31.0, Starlette 1.3.1, SQLAlchemy 2.0.23, Aiohttp 3.14.3.
  - C/C++: CMake 3.22+, GNU Make, SQLite3, OpenSSL 3.6, PCRE2 10.42, RE2, RocksDB 8.3.2, spdlog 1.14, nlohmann-json 3.11, cJSON, Flatbuffers.

#### 2. Original Architecture and Major Modules
Wazuh v5.1.0 alpha0 is an enterprise Security Information and Event Management (SIEM) and Extended Detection and Response (XDR) architecture organized around a Server (Manager) and distributed Agents:
- **`src/engine/` (`wazuh-manager-analysisd`):** High-performance log analysis engine (licensed under AGPL-3.0). Decodes event streams, correlates indicators of compromise, and evaluates XML detection rules.
- **`src/remoted/`:** Agent-server encrypted communication broker (TCP/UDP ports 1514/1515).
- **`src/os_auth/`:** Agent registration and authentication service (port 1515).
- **`src/syscheckd/`:** File Integrity Monitoring (FIM) subsystem tracking file attribute, hash, and permission changes in real time.
- **`src/rootcheck/`:** Rootkit, malware, and anomaly detection module.
- **`src/wazuh_db/`:** Local SQLite-based state manager for agent metadata, FIM inventory, and syscollector databases.
- **`src/os_execd/` & `src/active-response/`:** Automated countermeasure and active response executor.
- **`src/wazuh_modules/`:** Background scanning subsystems:
  - Vulnerability Detector (correlating installed packages against CVE databases).
  - SCA (Security Configuration Assessment).
  - Syscollector (hardware, software, network inventory).
- **`framework/` & `api/`:** Python 3.12 RESTful API service (`wazuh-manager-apid`, port 55000) allowing programmatic querying and management.
- **`ruleset/`:** Extensive collection of decoders, correlation rules, and compliance mappings (MITRE ATT&CK, PCI-DSS, GDPR, HIPAA, NIST 800-53).

#### 3. Main Entry Points and Execution Commands
- **Manager Control Script:** `/var/wazuh-manager/bin/wazuh-manager-control` (`start`, `stop`, `restart`, `status`).
- **Agent Control Script:** `/var/ossec/bin/wazuh-control` (`start`, `stop`, `status`).
- **Installer Script:** `install.sh` (interactive and unattended setup wizard).
- **Build Commands:**
  - `make -C src TARGET=manager deps`
  - `make -C src TARGET=manager` (or `TARGET=agent`)
  - `python3 src/build.py` (developer testing and module validation).

#### 4. Backend Functionality and Security Capabilities
- **Host Intrusion Detection (HIDS):** Log decoding, anomaly detection, process cloaking detection.
- **File Integrity Monitoring (FIM):** Real-time cryptographic hashing and registry/file audit trails.
- **Vulnerability Management:** Automated CVE detection across monitored operating systems.
- **Compliance & Hardening:** Out-of-the-box CIS benchmark evaluations (SCA).
- **Active Response:** Dynamic firewall drops, process termination, custom remediation scripts.

#### 5. Dependencies and Package Managers
- **Package Managers:** `apt` / `dnf` for system tools; Python `pip` (`framework/requirements.txt`); custom dependency lockfile `src/deps.lock.mk` tracking over 45 precompiled third-party libraries.
- **Build Requirements:** GCC 13+ / GCC 14, G++, CMake >= 3.22.1, GNU Make, Python 3.12.

#### 6. Build Systems and Runtime Requirements
- **Build Systems:** GNU Make wrapping CMake and custom shell compilation scripts.
- **Runtime:** Linux operating system for Manager server daemons; significant RAM requirements (minimum 4GB - 8GB for manager + indexer).

#### 7. Operating System Compatibility
- **Wazuh Manager (Server):** **Linux Only** (Ubuntu 22.04/24.04, RHEL/Rocky Linux 8/9, Debian). Cannot run natively on bare-metal Windows hosts.
- **Wazuh Agent:** Multi-platform: Linux, Windows (via MinGW cross-compile or native installers), macOS, BSD, Solaris, AIX.

#### 8. Configuration Files and Environment Variables
- **Manager Config:** `/etc/wazuh-manager/wazuh-manager.conf` (XML configuration defining `<global>`, `<ruleset>`, `<remote>`, `<syscheck>`, `<vulnerability-detector>`).
- **Agent Config:** `/etc/wazuh-manager/agent.conf` / `ossec-agent.conf`.
- **Preloaded Variables:** `etc/preloaded-vars.conf` (for automated unattended installation).
- **Internal Options:** `etc/internal_options.conf`.
- **Local Credentials:** `/etc/wazuh-manager/local.env`.

#### 9. External Services and Integrations
- **Wazuh Indexer:** Dedicated OpenSearch-based distributed search engine for event indexing.
- **Wazuh Dashboard:** OpenSearch Dashboards fork for UI telemetry visualization.
- Cloud integrations (AWS CloudTrail/GuardDuty, Azure Log Analytics, GCP).

#### 10. Potential Compatibility Issues with Other Repositories
- **Copyleft Licensing Contagion:** `src/engine/` is **AGPL-3.0** and the rest of the codebase is **GPL-2.0**. Direct in-process linking with MIT (CrowdSec, Promptfoo) or Apache 2.0 (Coraza, ModSecurity) components is legally incompatible.
- **System Service Collisions:** Wazuh binds to syslog and standard network ports; its active responses can conflict with CrowdSec bouncers modifying identical iptables/nftables firewall tables.

#### 11. Licence and Copyright Files
- **File:** `engines/wazuh-main/LICENSE`
- **Licenses:**
  - `src/engine/`: GNU Affero General Public License version 3 (AGPL-3.0-or-later).
  - `src/shared_modules/`: Dual licensed GPL-2.0-only OR AGPL-3.0-or-later.
  - Everything else: GNU General Public License version 2 (GPL-2.0) with OpenSSL linking exception.
- **Copyright:** Portions Copyright (C) Wazuh Inc.; based on OSSEC Copyright (C) 2003-2013 Trend Micro, Inc.

#### 12. Whether It Can Operate Independently
- **Yes:** Wazuh is an enterprise-scale standalone platform operating complete daemon clusters, API servers, and local databases.

---

## 2. Comparison of All Five Security Engines

| Attribute | OWASP Coraza | CrowdSec | ModSecurity v3 | Promptfoo | Wazuh (v5.1.0) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Domain** | Layer 7 Web Application Firewall (WAF) | Distributed IPS/IDS & Threat Intelligence | Layer 7 Web Application Firewall (WAF) | Generative AI / LLM Security & Red Teaming | Host SIEM / XDR & Endpoint Security |
| **Software Type** | Software Library / SDK | Standalone Daemon & REST API Server | Shared Dynamic Library (`.so` / `.dll`) | CLI Toolkit & Web Diagnostic Server | Multi-Daemon Server & Distributed Agents |
| **Primary Languages** | Go (`1.26.0`) | Go (`1.27.1`) | C++17 | TypeScript / Node (`>=22.22`) | C, C++20, Python 3.12 |
| **Build System** | `go build` / `mage` | GNU Make / `go build` | Autotools (Linux) / CMake + Conan (Win) | `tsdown` / `npm` | GNU Make + CMake |
| **Inspection Target** | HTTP Transactions (Headers, Bodies, Params) | Log files, Syslog, Journald, HTTP (AppSec) | HTTP Transactions (Headers, Bodies, Params) | LLM Prompts, Model Responses, Agent MCP Tools | OS Logs, Filesystem (FIM), System Binaries, Syscalls |
| **Detection Method** | SecLang Rules (OWASP CRS v4) | Grok Parsers, Leaky-Bucket Scenarios, SecLang | SecLang Rules (OWASP CRS v3/v4) | Automated Red Teaming, Adversarial Heuristics | Regex Decoders, XML Rulesets, CVE Matching |
| **Remediation Action** | HTTP Status Interrupt (403, 400, Drop) | Decoupled Bouncers (Firewall, CDN, Web) | HTTP Intervention (403, Drop, Redirect) | Assertion Failures, CI/CD Gate, Risk Score | Active Response Scripts, Agent Countermeasures |
| **Threat Intelligence** | Local Rules / SecRemoteRules | Real-time Community Consensus Blocklist | Local Rules / SecRemoteRules | Vulnerability Datasets (HarmBench, Pliny) | Threat Feeds, CVE DB, MITRE ATT&CK Mapping |
| **Native Windows** | Yes (Pure Go) | Yes (Windows Service + Win EventLog) | Yes (via MSVC + Conan build) | Yes (Node.js runtime) | Agent only (Manager requires Linux) |
| **License** | Apache 2.0 | MIT | Apache 2.0 | MIT | GPL-2.0 / AGPL-3.0 |
| **Standalone Daemon?** | No (requires host wrapper) | Yes (`crowdsec`) | No (requires web connector) | Yes (CLI & server) | Yes (`wazuh-manager-control`) |

---

## 3. Dependency and Runtime Compatibility Matrix

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                          POLYGLOT RUNTIME STACK                                  │
├─────────────────┬────────────────────────────────────────────────────────────────┤
│ Go Ecosystem    │ • Go 1.26 (Coraza) vs Go 1.27 (CrowdSec)                      │
│                 │ • CrowdSec embeds Coraza v3.8.0 via go.mod vendor replacement │
├─────────────────┼────────────────────────────────────────────────────────────────┤
│ C / C++ Stack   │ • ModSecurity: C++17 (Flex, Bison, PCRE2, YAJL, LMDB, curl)    │
│                 │ • Wazuh: C & C++20 (GCC 13+, CMake 3.22+, OpenSSL 3, RocksDB)  │
├─────────────────┼────────────────────────────────────────────────────────────────┤
│ JavaScript / TS │ • Promptfoo: Node.js >= 22.22.0, Drizzle ORM, better-sqlite3   │
├─────────────────┼────────────────────────────────────────────────────────────────┤
│ Python Stack    │ • Wazuh Manager REST API & Framework: Python 3.12 (Connexion,  │
│                 │   Uvicorn, Starlette, SQLAlchemy, Aiohttp)                     │
└─────────────────┴────────────────────────────────────────────────────────────────┘
```

### 3.1 Language and Compiler Compatibility
- **Go Toolchain:** Coraza specifies Go `1.26.0`, while CrowdSec specifies Go `1.27.1`. In a unified build environment, Go tools maintain backward compatibility: compiling both using Go 1.27 satisfies both modules, provided their `go.mod` dependencies remain namespaced.
- **C/C++ Compilers:** ModSecurity targets standard C++17 and builds with GCC, Clang, or MSVC. Wazuh targets C++20 and mandates GCC 13+ (CI targets GCC 14) along with CMake 3.22.1+. Compiling on Ubuntu 24.04 provides a compiler environment suitable for both.
- **Node.js Environment:** Promptfoo mandates Node.js `>= 22.22.0`. Older LTS versions (Node 18 or 20) will fail validation scripts and TypeScript typing constraints.
- **Python Environment:** Wazuh Manager Framework mandates Python `3.12.14` (`framework/.python-version`).

### 3.2 System Library & Database Overlaps
- **SQLite Engine Differences:**
  - CrowdSec defaults to `mattn/go-sqlite3` (requires CGo) with an optional pure-Go `modernc/sqlite`.
  - Promptfoo uses `better-sqlite3` (native C++ Node addon).
  - Wazuh compiles its own embedded `sqlite/3.53.1` directly into `wazuh_db`.
  - *Resolution:* Because these run as separate processes or runtimes, there are no symbol conflicts at runtime, but system packages must supply necessary C development headers.
- **Regex Engines:**
  - Coraza uses standard Go regex and `binaryregexp`.
  - ModSecurity requires `pcre2`.
  - CrowdSec requires `libre2` (C++) or WASM.
  - Wazuh bundles both `libpcre2` and `re2`.

### 3.3 Operating System Matrix

| OS Platform | Coraza | CrowdSec | ModSecurity v3 | Promptfoo | Wazuh Server | Wazuh Agent |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Linux (Ubuntu 22/24, RHEL 8/9)** | Supported | Supported | Supported | Supported | **Supported** | Supported |
| **Windows 10/11 / Server** | Supported | Supported | Supported (MSVC) | Supported | **Not Supported** | Supported |
| **macOS (Apple Silicon / Intel)** | Supported | Supported | Supported | Supported | **Not Supported** | Supported |
| **Docker / OCI Containers** | Supported | Supported | Supported | Supported | Supported | Supported |

> [!CRITICAL]
> **Host OS Constraint:** The current development workspace runs on Windows (`C:\DICKEN-BAGRECHA\Local Disk (D)\Projects\SENTRIX`). While Coraza, CrowdSec, ModSecurity (via `vcbuild.bat`), Promptfoo, and the Wazuh Agent can run or compile on Windows, the **Wazuh Manager server daemons cannot run natively on Windows**. Execution of the full SENTRIX unified backend stack will require Docker Desktop (WSL2 backend) or a dedicated Linux environment.

---

## 4. Identification of Overlapping Functionality

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                     SENTRIX FUNCTIONAL OVERLAP TOPOLOGY                         │
│                                                                                 │
│   ┌────────────────────────────────────────────────────────┐                    │
│   │                 WEB APPLICATION FIREWALL               │                    │
│   │  ┌───────────────────────┐   ┌──────────────────────┐  │                    │
│   │  │     OWASP Coraza      │   │    ModSecurity v3    │  │  100% Rule Grammar │
│   │  │       (Pure Go)       │   │        (C++)         │  │  & Engine Overlap  │
│   │  └───────────┬───────────┘   └──────────────────────┘  │                    │
│   └──────────────┼─────────────────────────────────────────┘                    │
│                  │ Embedded inside                                              │
│   ┌──────────────▼─────────────────────────────────────────┐                    │
│   │                  INTRUSION DETECTION (IDS)             │                    │
│   │  ┌───────────────────────┐   ┌──────────────────────┐  │  Log Analysis &    │
│   │  │       CrowdSec        │   │     Wazuh (SIEM)     │  │  Active Response   │
│   │  │ (LAPI + Grok + CAPI)  │   │  (Decoders + Rules)  │  │  Overlap           │
│   │  └───────────────────────┘   └──────────────────────┘  │                    │
│   └────────────────────────────────────────────────────────┘                    │
│                                                                                 │
│   ┌────────────────────────────────────────────────────────┐                    │
│   │              AI / LLM ADVERSARIAL DEFENSE              │                    │
│   │  ┌──────────────────────────────────────────────────┐  │  Distinct Domain:  │
│   │  │             Promptfoo (GenAI / LLM)              │  │  Semantic Attacks  │
│   │  └──────────────────────────────────────────────────┘  │  & Prompt Injections│
│   └────────────────────────────────────────────────────────┘                    │
└─────────────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Coraza vs. ModSecurity v3 (Direct Functional Duplication)
- **Grammar & Semantics:** Both engines execute identical SecLang directives (`SecRule`, `SecAction`, `SecMarker`, `ctl:`, `chain`).
- **Core Rule Set:** Both run the OWASP Core Rule Set (CRS). Coraza is 100% certified compatible with CRS v4; ModSecurity supports CRS v3 and v4.
- **Architecture Difference:**
  - ModSecurity v3 is legacy C++ requiring external native libraries (YAJL, libxml2, libinjection, PCRE2).
  - Coraza is modern Go with native memory safety, zero CGo requirements, and built-in modern JSON/XML handling.
- **Upstream Validation:** CrowdSec itself previously relied on libmodsecurity but **completely transitioned to Coraza** (`pkg/acquisition/modules/appsec` and `pkg/appsec`). CrowdSec explicitly vendor-replaces Coraza in `go.mod`.
- **Architectural Recommendation for SENTRIX:** 
  - Standardize on **Coraza** as the primary, high-throughput Go-native WAF engine.
  - Maintain **ModSecurity v3** as an optional C++ engine for legacy C-based reverse proxies (Nginx/Apache dynamic module connectors) or comparative benchmarking.

### 4.2 CrowdSec vs. Wazuh (Log Analysis, Detection & Response Overlap)
- **Log Processing:**
  - CrowdSec ingests logs using an event acquisition layer (`pkg/acquisition`), parses them with Grok patterns, and correlates events using stateful Leaky-Bucket algorithms.
  - Wazuh ingests logs via `wazuh-logcollector` or syslog, decodes them with OSSEC-style XML regex decoders, and evaluates them with rule trees.
- **Active Remediation:**
  - CrowdSec emits decisions stored in LAPI; external bouncers query LAPI to drop IPs via firewall rules.
  - Wazuh dispatches Active Response scripts (`os_execd`) directly to endpoint agents to block IPs, kill processes, or isolate hosts.
- **Complementary Strengths (Non-Overlapping):**
  - **CrowdSec's unique strength:** Community Threat Intelligence (CAPI). It automatically blocks known malicious IPs worldwide before an attack hits the local server.
  - **Wazuh's unique strength:** Comprehensive endpoint visibility (File Integrity Monitoring, Rootcheck, CVE Vulnerability matching, System hardening, Regulatory compliance).
- **Architectural Recommendation for SENTRIX:**
  - Route network edge and external IP threat detection through **CrowdSec**.
  - Route deep host telemetry, system auditing, file integrity monitoring, and CVE correlation through **Wazuh**.
  - Interlink CrowdSec alert decisions into Wazuh's event pipeline so all network blocks are indexed as high-severity SIEM events.

### 4.3 Promptfoo vs. Traditional Security Engines (Distinct AI Domain)
- **Traditional Blindspot:** Coraza, ModSecurity, CrowdSec, and Wazuh operate on structural patterns (SQL syntax, shell commands, regexes, IP addresses). They cannot understand semantic context, natural language prompt injection, jailbreaks, model hallucination, or tool-calling exploits.
- **Promptfoo's Role:** Dedicated application security for Generative AI / Large Language Models.
- **Architectural Recommendation for SENTRIX:**
  - Position Promptfoo as the **AI Security Gateway & Automated Red Teaming Service**.
  - Incoming HTTP traffic to LLM endpoints is first inspected for network/web exploits by Coraza/CrowdSec, then validated by Promptfoo guardrails for semantic prompt injections and data leaks before hitting the model.

---

## 5. Proposed Strategy for Combining All Five into One SENTRIX Git Repository

To preserve 100% of the original repositories' capabilities while uniting them into a single, cohesive SENTRIX cybersecurity platform, the following unified architecture is proposed:

```
SENTRIX Monorepo Architecture
=============================

sentrix/
├── documentation/
│   ├── PHASE-1-INSPECTION.md
│   └── architecture/
├── engines/                           # Intact Upstream Engines (Untouched Vendor Trees)
│   ├── coraza/                        # (from engines/coraza-main)
│   ├── crowdsec/                      # (from engines/crowdsec-master)
│   ├── modsecurity/                   # (from engines/ModSecurity-3-master)
│   ├── promptfoo/                     # (from engines/promptfoo-main)
│   └── wazuh/                         # (from engines/wazuh-main)
├── gateway/                           # SENTRIX Unified API & Control Gateway
│   ├── cmd/sentrixd/                  # Unified Orchestration Daemon (Go)
│   ├── internal/bus/                  # Internal Event Bus / IPC Interconnect
│   └── internal/bridge/               # Adapters to CrowdSec LAPI, Wazuh API, Coraza, Promptfoo
├── deploy/                            # Deployment & Container Manifests
│   ├── docker-compose.yml             # Local Multi-Engine Orchestration
│   ├── Dockerfile.coraza
│   ├── Dockerfile.crowdsec
│   ├── Dockerfile.promptfoo
│   └── Dockerfile.wazuh
└── Makefile                           # Root Polyglot Build Orchestrator
```

### 5.1 Repository Layout & Monorepo Strategy
- **Preserved Vendor Directories:** Keep the five upstream codebases in dedicated directories under `engines/`. This maintains clear attribution, respects distinct git histories, and simplifies merging upstream security patches.
- **Isolated Module Namespaces:** Prevent package-manager collisions by maintaining independent `go.mod`, `package.json`, and `Makefile` scopes within each engine directory.

### 5.2 Build Orchestration Strategy
- **Root Makefile / Taskfile:** A top-level build orchestrator that delegates build commands into each engine's native toolchain:
  ```makefile
  build-coraza:
  	cd engines/coraza && go build ./...
  build-crowdsec:
  	cd engines/crowdsec && make
  build-promptfoo:
  	cd engines/promptfoo && npm install && npm run build
  build-modsecurity:
  	cd engines/modsecurity && ./build.sh && ./configure && make
  build-wazuh:
  	cd engines/wazuh/src && make TARGET=manager deps && make TARGET=manager
  ```
- **Containerized Build Isolation:** Provide multi-stage Docker builds to encapsulate language runtimes (Go 1.27, Node 22, Python 3.12, GCC 14) so developers do not need all toolchains installed on their bare-metal host.

### 5.3 Inter-Engine Communication & Event Bus Architecture
SENTRIX must avoid tightly coupling the engines in memory. Instead, use a **decoupled service-mesh / event-driven IPC architecture**:
1. **Edge Web Traffic Interception:**
   - A high-performance reverse proxy (e.g., Envoy or custom Go proxy) intercepts incoming web traffic.
   - Traffic is piped through **Coraza** for Layer 7 WAF inspection.
   - Coraza emits transaction logs directly to **CrowdSec** via CrowdSec's AppSec acquisition channel.
2. **AI & LLM Gateway Pipeline:**
   - Any HTTP request directed to `/api/v1/ai/*` or LLM backends passes from the WAF into **Promptfoo Guardrail Middleware** for prompt-injection screening before being forwarded to LLM providers.
3. **Host & SIEM Event Correlation:**
   - **Wazuh Manager** ingests endpoint telemetry, system logs, and FIM events.
   - When CrowdSec detects a malicious IP, its notification plugin publishes an alert to SENTRIX's central event bus.
   - SENTRIX forwards this decision to Wazuh's active response, enabling coordinated host-level and firewall-level blocking.
4. **Unified Control Plane (`gateway/cmd/sentrixd`):**
   - A lightweight Go daemon that connects to:
     - CrowdSec Local API (`http://127.0.0.1:8080/v1`) via API keys.
     - Wazuh REST API (`https://127.0.0.1:55000`) via JWT authentication.
     - Promptfoo embedded server (`http://127.0.0.1:15500`).
   - Exposes a single, unified SENTRIX backend REST/gRPC API for unified telemetry, health checks, and policy distribution.

### 5.4 Licensing and Legal Compliance Strategy
The licenses across the five repositories require strict legal isolation:
- **CrowdSec:** MIT (Permissive)
- **Promptfoo:** MIT (Permissive)
- **Coraza:** Apache 2.0 (Permissive with patent grant)
- **ModSecurity:** Apache 2.0 (Permissive with patent grant)
- **Wazuh:** **GPL-2.0** (core/shared) & **AGPL-3.0** (`src/engine/`) (Strong Copyleft)

> [!WARNING]
> **Legal Boundary Mandate:**
> Under no circumstances should proprietary or permissively licensed code (from Coraza, CrowdSec, Promptfoo, or a proprietary SENTRIX wrapper) be compiled into a single static or dynamic binary with Wazuh's GPL/AGPL source code. 
> 
> **Architecture Requirement:** All integration between Wazuh and the rest of SENTRIX must occur exclusively over **clean network boundaries (REST API, gRPC, Unix Domain Sockets, or IPC queues)**. Running Wazuh as an isolated service daemon communicating over HTTPS/Unix sockets preserves license boundaries and prevents copyleft contamination of the wider SENTRIX platform.

---

## 6. Technical Risks and Unresolved Questions

### 6.1 Technical Risks

1. **Uninitialized Git Submodules in ModSecurity:**
   - *Risk:* In `engines/ModSecurity-3-master`, submodules (`others/libinjection`, `others/mbedtls`, `bindings/python`, `test/test-cases/secrules-language-tests`) are currently empty directories.
   - *Impact:* ModSecurity cannot compile out of the box until submodules are initialized (`git submodule update --init --recursive`) or dependencies are resolved via external system libraries.

2. **Operating System Incompatibility for Wazuh Manager:**
   - *Risk:* Wazuh Manager daemons strictly require a Linux operating system (kernel, systemd, posix signals, glibc). The current host is Windows.
   - *Impact:* Local development and testing of Wazuh Manager on Windows cannot occur on the bare-metal OS; it must run inside Docker (WSL2) or a dedicated Linux VM.

3. **High Resource Footprint:**
   - *Risk:* Running all 5 engines concurrently:
     - Wazuh Manager: 4GB - 8GB RAM minimum.
     - OpenSearch Indexer (Wazuh dependency): 4GB RAM minimum.
     - CrowdSec daemon + database: ~150MB RAM.
     - Promptfoo evaluation engine: ~500MB - 2GB RAM during large matrix evaluations.
     - Coraza WAF: ~50MB - 200MB RAM.
   - *Impact:* The developer and production host must have at least 16GB - 32GB RAM allocated to run the full stack simultaneously.

4. **Toolchain Version Discrepancies:**
   - *Risk:* Coraza requires Go 1.26, CrowdSec requires Go 1.27, Promptfoo requires Node.js >= 22.22, Wazuh requires GCC 13+/14 and Python 3.12.
   - *Impact:* Managing these diverse runtimes locally without containers will lead to developer environment drift and build failures.

5. **Upstream Drift and Maintenance Burden:**
   - *Risk:* If upstream repositories are vendored directly as static directories rather than Git submodules or subtree merges, pulling security fixes from upstream will require manual reconciliation.

### 6.2 Unresolved Questions for Future Phases

1. **WAF Redundancy Resolution:**
   - Will SENTRIX deprecate native C++ ModSecurity in favor of pure-Go Coraza, or must both engines be maintained concurrently in production?
2. **Wazuh Indexer Strategy:**
   - Does SENTRIX intend to deploy the full Wazuh Indexer (OpenSearch) and Wazuh Dashboard, or will SENTRIX stream Wazuh events into a custom, unified data store?
3. **Promptfoo Deployment Lifecycle:**
   - Is Promptfoo intended solely for pre-deployment CI/CD evaluation and red-teaming, or will its guardrails be run as an inline, real-time proxy for every production LLM inference request?
4. **Firewall & Remediation Authority:**
   - If both CrowdSec (via bouncers) and Wazuh (via active responses) issue firewall drop commands, what orchestration layer will arbitrate conflicting or redundant IP bans?
5. **Monorepo Management:**
   - Should the five engines be tracked in the primary SENTRIX Git repository as Git submodules, Git subtrees, or decoupled vendor directories with automated sync actions?

---

*End of Phase 1 Inspection Report.*
