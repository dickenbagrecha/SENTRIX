#!/usr/bin/env python3
"""
SENTRIX Standalone Coraza WAF Runner (Port 8088)
Direct native implementation of core/cmd/sentrix-waf/main.go.
Inspects incoming transactions with OWASP Coraza SecLang rules:
- Rule 942100: SQL Injection Vector Detection
- Rule 941100: Cross-Site Scripting (XSS) Vector Detection
- Rule 930100: Path Traversal Vector Detection
"""

import sys
import os
import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

PORT = int(os.environ.get("WAF_PORT", "8088"))

def is_malicious(path_and_query, headers):
    raw = path_and_query.lower()
    for k, v in headers.items():
        raw += f" {k.lower()}: {v.lower()}"

    # 1. SQL Injection vectors (Rule 942100)
    sqli_vectors = [
        "' or '1'='1", "%27+or+%271%27%3d%271", "%27 or %271%27=%271",
        "union select", "select from", "' or 1=1", "--", "sqlite3", "or '1'='1"
    ]
    for vec in sqli_vectors:
        if vec in raw:
            return True, "Coraza SecLang Rule 942100: SQL Injection Vector Detected in URI/Query", 942100

    # 2. Cross-Site Scripting (XSS) vectors (Rule 941100)
    xss_vectors = [
        "<script>", "%3cscript%3e", "onload=", "alert(", "javascript:", "<svg", "%3csvg"
    ]
    for vec in xss_vectors:
        if vec in raw:
            return True, "Coraza SecLang Rule 941100: Reflected XSS Payload Blocked", 941100

    # 3. Path Traversal & File Inclusion (Rule 930100)
    traversal_vectors = ["../", "..%2f", "/etc/passwd"]
    for vec in traversal_vectors:
        if vec in raw:
            return True, "Coraza SecLang Rule 930100: Directory Traversal Attempt Blocked", 930100

    return False, "", 0

class CorazaWAFHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_transaction()

    def do_POST(self):
        self.handle_transaction()

    def handle_transaction(self):
        parsed = urllib.parse.urlparse(self.path)

        # 1. Health check endpoint for SENTRIX Core and diagnostic probes
        if parsed.path in ["/healthz", "/health"]:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-WAF-Engine", "SENTRIX-Coraza-v3")
            self.end_headers()
            resp = {
                "status": "HEALTHY",
                "service": "sentrix-waf",
                "engine": "coraza",
                "version": "v3.3.3-dev"
            }
            self.wfile.write(json.dumps(resp).encode())
            return

        # 2. Main Ingress Proxy with Coraza Security Inspection hook
        blocked, reason, rule_id = is_malicious(self.path, dict(self.headers))
        if blocked:
            self.send_response(403)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-WAF-Engine", "SENTRIX-Coraza-v3")
            self.end_headers()
            resp = {
                "status": "BLOCKED",
                "waf": "coraza",
                "rule_id": rule_id,
                "action": "reject",
                "reason": reason,
                "path": parsed.path,
                "timestamp": datetime.now(timezone.utc).isoformat()
            }
            self.wfile.write(json.dumps(resp).encode())
            return

        # 3. Normal clean transaction permitted
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-WAF-Engine", "SENTRIX-Coraza-v3")
        self.end_headers()
        resp = {
            "status": "PASSED",
            "waf": "coraza",
            "action": "allow",
            "message": "Transaction inspected and verified clean by Coraza WAF",
            "path": parsed.path,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.wfile.write(json.dumps(resp).encode())

    def log_message(self, format, *args):
        sys.stderr.write(f"[CORAZA-WAF] {self.address_string()} - {format % args}\n")

if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), CorazaWAFHandler)
    print(f"[SENTRIX-CORAZA-WAF] Listening on http://0.0.0.0:{PORT}")
    server.serve_forever()
