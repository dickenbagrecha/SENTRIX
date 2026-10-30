#!/usr/bin/env node
// ==============================================================================
// SENTRIX - Configuration, Schema, and Repository Integrity Validator
// Runs using Node.js runtime (cross-platform Windows/Linux/macOS)
// ==============================================================================

const fs = require('fs');
const path = require('path');

const ROOT_DIR = path.resolve(__dirname, '..');

let totalTests = 0;
let passedTests = 0;
let failedTests = 0;

function report(name, success, errorMsg = '') {
  totalTests++;
  if (success) {
    passedTests++;
    console.log(` [PASS] ${name}`);
  } else {
    failedTests++;
    console.error(` [FAIL] ${name}: ${errorMsg}`);
  }
}

console.log('=== SENTRIX Validation Suite ===\n');

// 1. Verify Original Upstream Repositories are Intact
console.log('--- 1. Upstream Repository Integrity ---');
const requiredEngines = [
  'engines/coraza-main',
  'engines/crowdsec-master',
  'engines/ModSecurity-3-master',
  'engines/promptfoo-main',
  'engines/wazuh-main'
];

for (const eng of requiredEngines) {
  const fullPath = path.join(ROOT_DIR, eng);
  const exists = fs.existsSync(fullPath) && fs.statSync(fullPath).isDirectory();
  const fileCount = exists ? fs.readdirSync(fullPath).length : 0;
  report(`Original repository '${eng}' intact (${fileCount} entries)`, exists && fileCount > 0);
}

// 2. Validate JSON Schemas and Sample Events
console.log('\n--- 2. SCSE Schema and Sample Validation ---');
try {
  const schemaPath = path.join(ROOT_DIR, 'schemas/scse-event-schema.json');
  const schemaRaw = fs.readFileSync(schemaPath, 'utf8');
  const schema = JSON.parse(schemaRaw);
  report('schemas/scse-event-schema.json is valid JSON', !!schema);

  const samplePath = path.join(ROOT_DIR, 'schemas/scse-sample-events.json');
  const sampleRaw = fs.readFileSync(samplePath, 'utf8');
  const samples = JSON.parse(sampleRaw);
  report('schemas/scse-sample-events.json is valid JSON', Array.isArray(samples));

  // Validate each sample against SCSE requirements
  const uuidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
  const validSeverities = new Set(['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']);
  const validActions = new Set(['BLOCKED', 'DROPPED', 'ALERTED', 'REMEDIATED', 'LOGGED', 'PASSED']);
  const validEngines = new Set(['coraza', 'crowdsec', 'modsecurity', 'promptfoo', 'wazuh', 'sentrix-core']);

  let allSamplesValid = true;
  for (const s of samples) {
    if (!uuidRegex.test(s.event_id)) {
      allSamplesValid = false;
      report(`Sample event ${s.event_id} UUID format`, false, 'Invalid UUID pattern');
      break;
    }
    if (!validSeverities.has(s.severity)) {
      allSamplesValid = false;
      report(`Sample event ${s.event_id} severity`, false, `Invalid severity ${s.severity}`);
      break;
    }
    if (!validActions.has(s.action_taken)) {
      allSamplesValid = false;
      report(`Sample event ${s.event_id} action`, false, `Invalid action ${s.action_taken}`);
      break;
    }
    if (!validEngines.has(s.engine)) {
      allSamplesValid = false;
      report(`Sample event ${s.event_id} engine`, false, `Unknown engine ${s.engine}`);
      break;
    }
  }
  report(`All ${samples.length} sample events conform to SCSE specifications`, allSamplesValid);
} catch (err) {
  report('Schema validation suite', false, err.message);
}

// 3. Validate Configuration Files Existence and Non-Empty
console.log('\n--- 3. Engine Configuration Files ---');
const configFiles = [
  'deploy/config/core.yaml',
  'deploy/config/coraza/waf.conf',
  'deploy/config/crowdsec/config.yaml',
  'deploy/config/crowdsec/acquis.yaml',
  'deploy/config/promptfoo/promptfoo.config.yaml',
  'deploy/config/wazuh/ossec.conf',
  'deploy/config/wazuh/local_rules.xml',
  'deploy/docker-compose.yml',
  'deploy/docker-compose.dev.yml'
];

for (const cfg of configFiles) {
  const fullPath = path.join(ROOT_DIR, cfg);
  const exists = fs.existsSync(fullPath);
  const size = exists ? fs.statSync(fullPath).size : 0;
  report(`Config '${cfg}' exists and is non-empty (${size} bytes)`, exists && size > 0);
}

// 4. Validate Core Go Source Structure
console.log('\n--- 4. SENTRIX Core Source Files ---');
const coreFiles = [
  'core/go.mod',
  'core/cmd/sentrixd/main.go',
  'core/cmd/sentrix-waf/main.go',
  'core/internal/config/config.go',
  'core/internal/logger/logger.go',
  'core/internal/orchestrator/orchestrator.go',
  'core/internal/orchestrator/health.go',
  'core/internal/auditor/runner.go',
  'core/internal/remediation/tracker.go',
  'core/internal/reporter/reporter.go',
  'core/internal/api/server.go',
  'core/pkg/models/scse.go',
  'core/pkg/models/target.go',
  'core/pkg/models/attack_category.go',
  'core/pkg/models/vulnerability.go',
  'core/tests/core_test.go',
  'documentation/SECURITY-TESTING-MODEL.md'
];

for (const cf of coreFiles) {
  const fullPath = path.join(ROOT_DIR, cf);
  const exists = fs.existsSync(fullPath);
  const size = exists ? fs.statSync(fullPath).size : 0;
  report(`Core component '${cf}' (${size} bytes)`, exists && size > 0);
}

// 5. Summary
console.log(`\n========================================`);
console.log(`Validation Results: ${passedTests}/${totalTests} Passed (${failedTests} Failed)`);
console.log(`========================================\n`);

if (failedTests > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
