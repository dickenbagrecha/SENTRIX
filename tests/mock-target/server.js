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

    // Default 404
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'endpoint not found', path: pathname }));
  });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[SYNTHETIC-TARGET] Listening on http://0.0.0.0:${PORT} in ${currentMode.toUpperCase()} mode`);
});
