#!/usr/bin/env node

/**
 * NEXUS Cloudflare Security Audit Validation Runner
 * 
 * Validates findings.json and coverage-ledger.json using the official Cloudflare
 * security-audit validators. Bypasses POSIX-only file descriptor flags (O_NOFOLLOW/O_NONBLOCK)
 * to run reliably on Windows, Linux, and macOS.
 */

const fs = require('fs');
const path = require('path');

// Locate global or user skill validators
const candidates = [
  path.join(process.env.USERPROFILE || process.env.HOME || '', '.agents', 'skills', 'security-audit'),
  path.join(process.env.USERPROFILE || process.env.HOME || '', '.gemini', 'config', 'skills', 'security-audit')
];

let skillDir = candidates.find(dir => fs.existsSync(path.join(dir, 'validate-findings.cjs')));

if (!skillDir) {
  console.error('[!] Cloudflare security-audit skill directory not found in ~/.agents/skills or ~/.gemini/config/skills');
  process.exit(1);
}

const validateFindings = require(path.join(skillDir, 'validate-findings.cjs'));
const validateLedger = require(path.join(skillDir, 'validate-coverage-ledger.cjs'));
const schema = require(path.join(skillDir, 'report-schema.json'));

const assessmentDir = __dirname;
const findingsPath = path.join(assessmentDir, 'findings.json');
const ledgerPath = path.join(assessmentDir, 'coverage-ledger.json');

console.log('='.repeat(70));
console.log('CLOUDFLARE SECURITY AUDIT SKILL — NEXUS VALIDATION REPORT');
console.log('='.repeat(70));
console.log(`Using Validator Module: ${skillDir}`);
console.log(`Node Runtime: ${process.version} on ${process.platform}`);
console.log('-'.repeat(70));

let hasErrors = false;

// 1. Validate findings.json
console.log('\n[1/2] Validating findings.json against report-schema.json...');
if (!fs.existsSync(findingsPath)) {
  console.error(`  FAIL: File not found at ${findingsPath}`);
  hasErrors = true;
} else {
  try {
    const findings = JSON.parse(fs.readFileSync(findingsPath, 'utf8'));
    const errors = validateFindings.validateDocument(findings, schema);
    if (errors && errors.length > 0) {
      console.error(`  FAIL: ${errors.length} validation error(s) found in findings.json:`);
      errors.forEach((err, i) => console.error(`    ${i + 1}. ${err}`));
      hasErrors = true;
    } else {
      const confirmed = findings.filter(f => f.verdict === 'confirmed').length;
      const needsVal = findings.filter(f => f.verdict === 'needs_validation').length;
      const rejected = findings.filter(f => f.verdict === 'rejected').length;
      console.log(`  PASS: findings.json is 100% compliant with report-schema.json`);
      console.log(`        Total Findings: ${findings.length}`);
      console.log(`        Confirmed: ${confirmed} | Needs Validation: ${needsVal} | Rejected: ${rejected}`);
    }
  } catch (err) {
    console.error(`  FAIL: Exception parsing/validating findings.json: ${err.message}`);
    hasErrors = true;
  }
}

// 2. Validate coverage-ledger.json
console.log('\n[2/2] Validating coverage-ledger.json...');
if (!fs.existsSync(ledgerPath)) {
  console.error(`  FAIL: File not found at ${ledgerPath}`);
  hasErrors = true;
} else {
  try {
    const ledger = JSON.parse(fs.readFileSync(ledgerPath, 'utf8'));
    const errors = validateLedger.validateDocument(ledger);
    if (errors && errors.length > 0) {
      console.error(`  FAIL: ${errors.length} validation error(s) found in coverage-ledger.json:`);
      errors.forEach((err, i) => console.error(`    ${i + 1}. ${err}`));
      hasErrors = true;
    } else {
      console.log(`  PASS: coverage-ledger.json is 100% valid`);
      console.log(`        Validated Coverage Units: ${ledger.length}`);
    }
  } catch (err) {
    console.error(`  FAIL: Exception parsing/validating coverage-ledger.json: ${err.message}`);
    hasErrors = true;
  }
}

console.log('\n' + '='.repeat(70));
if (hasErrors) {
  console.log('RESULT: VALIDATION FAILED');
  process.exit(1);
} else {
  console.log('RESULT: ALL VALIDATION CHECKS PASSED (0 ERRORS)');
  console.log('='.repeat(70));
  process.exit(0);
}
