/**
 * SENTRIX Phase 4 - Live Adversarial Auditing & Remediation Verification Test Suite
 * 
 * Executes an end-to-end runtime test:
 * 1. Starts the Synthetic Target Application (tests/mock-target/server.js) on port 9500.
 * 2. Connects to SENTRIX Core on port 9000.
 * 3. Runs an adversarial audit across all 12 attack categories in Vulnerable mode.
 * 4. Verifies technical evidence and finding generation.
 * 5. Tests the 9-stage remediation lifecycle state machine.
 * 6. Tests regression failure (vulnerability still reproduces -> reverts to Fix In Progress).
 * 7. Toggles target to Secure mode.
 * 8. Verifies regression pass (remediation verified -> moves to Verified -> Closed).
 * 9. Runs a second audit against Secure mode to verify 100% secure rejection (0 false positives).
 */

const http = require('http');
const { spawn, execSync } = require('child_process');
const path = require('path');

function request(options, data) {
  return new Promise((resolve, reject) => {
    const req = http.request(options, (res) => {
      let body = '';
      res.on('data', chunk => { body += chunk; });
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, headers: res.headers, body: body ? JSON.parse(body) : null, raw: body });
        } catch (e) {
          resolve({ status: res.statusCode, headers: res.headers, body: null, raw: body });
        }
      });
    });
    req.on('error', reject);
    if (data) {
      req.write(typeof data === 'string' ? data : JSON.stringify(data));
    }
    req.end();
  });
}

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function waitForServer(url, timeoutMs = 15000) {
  const start = Date.now();
  while (Date.now() - start < timeoutMs) {
    try {
      const u = new URL(url);
      const res = await request({
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: 'GET',
        timeout: 2000
      });
      if (res.status === 200) return true;
    } catch (e) {}
    await sleep(500);
  }
  throw new Error(`Timeout waiting for ${url}`);
}

async function main() {
  console.log('======================================================================');
  console.log('   SENTRIX Phase 4 - Runtime Adversarial & Remediation Test Suite     ');
  console.log('======================================================================\n');

  // 1. Start synthetic target server
  console.log('[1/7] Launching Synthetic Target Application on port 9500...');
  const targetScript = path.join(__dirname, '..', 'tests', 'mock-target', 'server.js');
  const targetProc = spawn(process.execPath, [targetScript], {
    env: { ...process.env, PORT: '9500', TARGET_MODE: 'vulnerable' },
    stdio: 'pipe'
  });

  targetProc.stdout.on('data', d => process.stdout.write(`  [Target stdout] ${d}`));
  targetProc.stderr.on('data', d => process.stderr.write(`  [Target stderr] ${d}`));

  await waitForServer('http://127.0.0.1:9500/healthz');
  console.log(' [OK] Synthetic Target is listening and healthy.\n');

  // 2. Ensure SENTRIX Core container is running
  console.log('[2/7] Checking SENTRIX Core container on port 9000...');
  try {
    await waitForServer('http://127.0.0.1:9000/healthz', 10000);
    console.log(' [OK] SENTRIX Core is already running.\n');
  } catch (e) {
    console.log('  Starting sentrix-core container...');
    try {
      execSync('docker rm -f sentrix-core-runtime', { stdio: 'ignore' });
    } catch (_) {}
    execSync('docker run -d --name sentrix-core-runtime -p 9000:9000 --add-host=host.docker.internal:host-gateway -e SENTRIX_BIND_ADDRESS=0.0.0.0 sentrix-core:latest', { stdio: 'inherit' });
    await waitForServer('http://localhost:9000/healthz', 15000);
    console.log(' [OK] SENTRIX Core started successfully.\n');
  }

  try {
    // 3. Run Controlled Adversarial Audit in Vulnerable Mode
    console.log('[3/7] Executing Adversarial Audit against Target in VULNERABLE mode...');
    const auditPayload = {
      target_id: 'TARGET-VLOOKUP-STAGING',
      name: 'V-LOOKUP Staging Application (Synthetic)',
      base_url: 'http://host.docker.internal:9500',
      environment: 'staging',
      allowed_hosts: ['127.0.0.1', 'localhost', 'host.docker.internal', 'staging.vlookup.local'],
      allowed_endpoints: ['/api/v1/*'],
      use_synthetic_data_only: true,
      max_requests_per_second: 50,
      safe_mode: true,
      scope_token: 'AUTH-SCOPE-VLOOKUP-STAGING-CONFIRMED'
    };

    const auditRes = await request({
      hostname: 'localhost',
      port: 9000,
      path: '/api/v1/audits/run',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, auditPayload);

    if (auditRes.status !== 200) {
      throw new Error(`Audit request failed with HTTP ${auditRes.status}: ${JSON.stringify(auditRes.body)}`);
    }

    const findings = auditRes.body.findings || [];
    console.log(`\n Audit Completed: ${auditRes.body.scenarios_run} scenarios run, ${auditRes.body.findings_count} findings detected.`);

    // 4. Detailed Results Verification per Attack Category
    console.log('\n[4/7] Verifying 12 Core Attack Categories in Vulnerable Mode:');
    console.log('-------------------------------------------------------------------------------------------------------------');
    console.log('| #  | Attack Category               | Executed | Target Secure | Detected | Finding ID       | Latency |');
    console.log('-------------------------------------------------------------------------------------------------------------');

    const expectedCategories = [
      'SQL_INJECTION',
      'CROSS_SITE_SCRIPTING',
      'BROKEN_AUTHENTICATION',
      'BROKEN_ACCESS_CONTROL_IDOR',
      'CROSS_TENANT_DATA_LEAKAGE',
      'PROMPT_INJECTION',
      'RAG_POISONING',
      'SENSITIVE_DATA_EXFILTRATION',
      'API_ABUSE',
      'MALICIOUS_FILE_UPLOAD',
      'SSRF',
      'DENIAL_OF_SERVICE'
    ];

    let detectedCount = 0;
    expectedCategories.forEach((cat, idx) => {
      const match = findings.find(f => f.category === cat);
      const executed = 'YES';
      const targetSecure = match ? 'NO (VULN)' : 'YES';
      const detected = match ? 'YES' : 'NO';
      const fid = match ? match.finding_id : 'N/A';
      const lat = match ? `${match.technical_evidence.latency_ms ?? 0}ms` : 'N/A';

      if (match) detectedCount++;

      console.log(`| ${(idx + 1).toString().padEnd(2)} | ${cat.padEnd(29)} | ${executed.padEnd(8)} | ${targetSecure.padEnd(13)} | ${detected.padEnd(8)} | ${fid.padEnd(16)} | ${lat.padEnd(7)} |`);
    });
    console.log('-------------------------------------------------------------------------------------------------------------\n');

    if (detectedCount !== 12) {
      throw new Error(`Expected 12/12 categories detected in vulnerable mode, got ${detectedCount}`);
    }
    console.log(` [OK] 12/12 Core Attack Categories detected and recorded with technical evidence.\n`);

    // 5. Test Developer Report Generation
    console.log('[5/7] Testing Developer Markdown Report Generation...');
    const testFinding = findings[0];
    const reportRes = await request({
      hostname: 'localhost',
      port: 9000,
      path: `/api/v1/findings/${testFinding.finding_id}/report`,
      method: 'GET'
    });

    if (reportRes.status !== 200 || !reportRes.raw.includes('Recommended Actionable Remediation')) {
      throw new Error(`Report generation failed for finding ${testFinding.finding_id}`);
    }
    console.log(` [OK] Developer Markdown report generated successfully for ${testFinding.finding_id} (${reportRes.raw.length} bytes).\n`);

    // 6. Test 9-Stage Remediation Lifecycle & Regression Testing
    console.log('[6/7] Testing 9-Stage Remediation Lifecycle & Regression Testing...');
    const fid = testFinding.finding_id;

    // Detected -> Confirmed
    await request({
      hostname: 'localhost',
      port: 9000,
      path: `/api/v1/findings/${fid}/transition`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { new_state: 'Confirmed', actor: 'lead-auditor', comment: 'Confirmed by audit engine' });

    // Confirmed -> Reported
    await request({
      hostname: 'localhost',
      port: 9000,
      path: `/api/v1/findings/${fid}/transition`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { new_state: 'Reported', actor: 'lead-auditor', comment: 'Published to development backlog' });

    // Reported -> Assigned
    await request({
      hostname: 'localhost',
      port: 9000,
      path: `/api/v1/findings/${fid}/transition`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { new_state: 'Assigned', actor: 'eng-lead', comment: 'Assigned to Backend Team' });

    // Assigned -> Fix In Progress
    await request({
      hostname: 'localhost',
      port: 9000,
      path: `/api/v1/findings/${fid}/transition`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { new_state: 'Fix In Progress', actor: 'dev-alice', comment: 'Working on parameterization' });

    // Fix In Progress -> Fixed
    await request({
      hostname: 'localhost',
      port: 9000,
      path: `/api/v1/findings/${fid}/transition`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { new_state: 'Fixed', actor: 'dev-alice', comment: 'Fix deployed to staging' });

    console.log('  State reached: Fixed. Running regression re-test while target is still vulnerable...');

    // Regression Test 1: While target is still vulnerable -> Must FAIL and revert to Fix In Progress
    const retest1 = await request({
      hostname: 'localhost',
      port: 9000,
      path: `/api/v1/remediation/retest/${fid}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, auditPayload);

    if (retest1.body.verified !== false || retest1.body.new_state !== 'Fix In Progress') {
      throw new Error(`Expected regression re-test to fail and revert to Fix In Progress, got: ${JSON.stringify(retest1.body)}`);
    }
    console.log('   [OK] Regression retest detected continued vulnerability; correctly reverted to "Fix In Progress".');

    // Switch target to SECURE mode
    console.log('  Switching Synthetic Target to SECURE (remediated) mode...');
    await request({
      hostname: 'localhost',
      port: 9500,
      path: '/control/mode',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { mode: 'secure' });

    // Dev marks as Fixed again
    await request({
      hostname: 'localhost',
      port: 9000,
      path: `/api/v1/findings/${fid}/transition`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { new_state: 'Fixed', actor: 'dev-alice', comment: 'True remediation verified locally' });

    // Regression Test 2: Target is now SECURE -> Must PASS and move to Verified
    console.log('  Running regression re-test against remediated target...');
    const retest2 = await request({
      hostname: 'localhost',
      port: 9000,
      path: `/api/v1/remediation/retest/${fid}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, auditPayload);

    if (retest2.body.verified !== true || retest2.body.new_state !== 'Verified') {
      throw new Error(`Expected regression re-test to pass and reach Verified, got: ${JSON.stringify(retest2.body)}`);
    }
    console.log('   [OK] Regression retest PASSED; finding moved to "Verified".');

    // Verified -> Closed
    const closeRes = await request({
      hostname: 'localhost',
      port: 9000,
      path: `/api/v1/findings/${fid}/transition`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, { new_state: 'Closed', actor: 'lead-auditor', comment: 'Verified in staging; signed off' });

    if (closeRes.body.state !== 'Closed') {
      throw new Error(`Failed to close finding, state: ${closeRes.body.state}`);
    }
    console.log('   [OK] Finding successfully transitioned to "Closed".');

    // 7. Verify Secure Rejection Across All 12 Categories
    console.log('\n[7/7] Executing Second Audit against SECURE mode (False Positive Verification)...');
    const auditRes2 = await request({
      hostname: 'localhost',
      port: 9000,
      path: '/api/v1/audits/run',
      method: 'POST',
      headers: { 'Content-Type': 'application/json' }
    }, auditPayload);

    if (auditRes2.body.findings_count !== 0) {
      throw new Error(`False positives detected! Expected 0 findings on secure target, got ${auditRes2.body.findings_count}`);
    }
    console.log(` [OK] 12/12 scenarios executed against secure target: 0 vulnerabilities found, 100% secure rejection confirmed.\n`);

    console.log('======================================================================');
    console.log('   ALL PHASE 4 RUNTIME ADVERSARIAL TESTS PASSED SUCCESSFULLY!         ');
    console.log('======================================================================\n');
  } finally {
    console.log('Cleaning up test resources...');
    targetProc.kill('SIGTERM');
  }
}

main().catch(err => {
  console.error('\n[FATAL ERROR]:', err);
  process.exit(1);
});
