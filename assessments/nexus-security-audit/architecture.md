   # NEXUS Application Security Architecture & Trust Boundary Map

**Audit Target:** NEXUS Enterprise AI Document Intelligence & Retrieval-Augmented Generation (RAG) Platform  
**Audit Standard:** Cloudflare Security Audit Skill (Full Audit Specification)  
**Evaluation Model:** Source-First, Read-Only Architectural Inspection  
**Date:** 2026-10-31  

---

## 1. System Overview & Technology Stack

NEXUS is an enterprise multi-tenant document processing and generative AI retrieval platform designed to extract, embed, index, and query corporate documentation through localized LLM inference.

### Core Technology Stack
- **Frontend Layer:** React 18, Vite, TypeScript, Tailwind CSS, Markdown Renderer (`react-markdown` / `DOMPurify`).
- **API Gateway & Routing:** Node.js HTTP / FastAPI asynchronous gateway (`tests/mock-target/server.js`, `deploy/docker/Dockerfile.nexus-backend`).
- **Data Persistence:** PostgreSQL 16 with `pgvector` (768-dimensional embeddings) and Row-Level Security (RLS) tables (`tenants`, `documents`, `conversations`).
- **Cache & Session Management:** Redis 7 (Alpine) handling session blacklists, query caching, and rate limiting.
- **AI / LLM Subsystem:** Local Ollama daemon (`llama3.2:3b`, `nomic-embed-text`) executing zero-external-network inference.
- **File Ingestion Engine:** Multi-format parser handling PDF, DOCX, XLSX, and compressed archives.

---

## 2. Attack Surfaces & External Entrypoints

```
[ Unauthenticated Public Internet / Client Browser ]
                     |
                     v (Port 9500 / 443)
+-------------------------------------------------------------+
|                  NEXUS API GATEWAY                          |
|  - Auth & Profile:       /api/v1/user/profile               |
|  - Session Validation:   /api/v1/auth/session-validate      |
|  - Search & Query:       /api/v1/search                     |
|  - Document Management:  /api/v1/documents/*                |
|  - Conversation History: /api/v1/tenants/:t/conversations/* |
|  - Assistant & RAG:      /api/v1/assistant/*, /api/v1/rag/* |
|  - Admin Config:         /api/v1/admin/tenants/:t/config    |
+-------------------------------------------------------------+
         |                       |                     |
         v (Internal TCP: 5432)  v (Internal TCP: 6379)v (Internal TCP: 11434)
+------------------+    +-----------------+    +-----------------+
|  PostgreSQL 16   |    |     Redis 7     |    |  Ollama Local   |
|  (pgvector, RLS) |    |  (Token Black-  |    |  (llama3.2:3b,  |
|                  |    |   list, Cache)  |    |   nomic-embed)  |
+------------------+    +-----------------+    +-----------------+
```

### Primary Surfaces
1. **Surface 1: Authentication & Identity (`surface:web-auth`):**
   - Endpoints: `/api/v1/user/profile`, `/api/v1/auth/session-validate`, `/api/v1/auth/logout`.
   - Protocols: HTTP/1.1 REST, Bearer JWT.
   - Trust Boundary: Untrusted Client -> Authenticated User Session.

2. **Surface 2: Multi-Tenant Data & Conversation Access (`surface:tenant-isolation`):**
   - Endpoints: `/api/v1/tenants/{tenant_id}/conversations/{conv_id}`, `/api/v1/documents/{doc_id}`.
   - Trust Boundary: Tenant Alpha Principal -> Tenant Beta Boundary (Cross-Tenant Barrier).

3. **Surface 3: Administrative Configuration (`surface:tenant-admin`):**
   - Endpoints: `/api/v1/admin/tenants/{tenant_id}/config`.
   - Trust Boundary: Standard Employee (`role: employee`) -> Tenant Administrator (`role: admin`).

4. **Surface 4: Document Ingestion & Parser Engine (`surface:document-ingestion`):**
   - Endpoints: `/api/v1/documents/upload`, `/api/v1/documents/parse-and-index`, `/api/v1/documents/decompress`.
   - Trust Boundary: Untrusted User File Upload -> Host File System & Ingestion Buffer.

5. **Surface 5: RAG Pipeline & Inference Gateway (`surface:rag-inference`):**
   - Endpoints: `/api/v1/rag/retrieve-verified`, `/api/v1/assistant/chat-stream`, `/api/v1/assistant/render-markdown`.
   - Trust Boundary: Untrusted Retrieved Chunks / User Queries -> LLM Context Window & Client Browser.

---

## 3. Trust Boundaries & Data Flow Constraints

### Trust Boundary 1: Tenant Data Isolation
- **Rule:** Tenant Alpha must never query, view, or mutate records, document embeddings, conversation logs, or cache keys belonging to Tenant Beta.
- **Enforcement Mechanism:** Cryptographically signed JWT claims, SQL Row-Level Security (`USING (tenant_id = current_setting('app.current_tenant_id'))`), and tenant-namespaced cache keys (`tenant:{tenant_id}:{key}`).

### Trust Boundary 2: Role Authorization (RBAC)
- **Rule:** Tenant configuration, global security settings, and audit logs require `admin` or `superadmin` role credentials.
- **Enforcement Mechanism:** Server-side RBAC validation; explicit rejection of unauthenticated headers (`X-User-Role`).

### Trust Boundary 3: AI Inference & Prompt Safety
- **Rule:** Data retrieved from third-party documents must be treated as untrusted text and cannot override system instructions.
- **Enforcement Mechanism:** XML demarcation of untrusted chunks, strict token input budgets (max 4,096 tokens), and HTML output escaping.

---

## 4. Subsystems & Component Classification

1. **`subsystem:identity`:** JWT decoding, token blacklist, session termination.
2. **`subsystem:tenancy`:** Path parameter validation, tenant context switching, RLS policies.
3. **`subsystem:documents`:** File type validation, decompression quota enforcers, metadata extraction.
4. **`subsystem:rag`:** Vector similarity search, chunk ranking, citation verification.
5. **`subsystem:inference`:** Ollama gateway, streaming token limiter, prompt sanitizer.
6. **`subsystem:cache`:** Redis client, cache key generator, TTL manager.
