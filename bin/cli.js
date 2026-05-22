#!/usr/bin/env node

'use strict';

const fs   = require('fs');
const path = require('path');
const { parseHAR }      = require('../src/parser');
const { runAllChecks }  = require('../src/checks');
const { generateReport } = require('../src/report');

const SEVERITY_ORDER = { high: 3, medium: 2, low: 1, info: 0 };

const args = process.argv.slice(2);

if (args.length === 0 || args.includes('--help') || args.includes('-h')) {
  console.log(`
Usage:
  har-security-scan <input.har> [options]

Options:
  --output, -o <file>    Output file path (default: auto-generated)
  --fail-on <severity>   Exit code 1 if findings exist at this severity or above (high|medium|low)
  --help,   -h           Show this help

Examples:
  har-security-scan capture.har
  har-security-scan capture.har --output my-report.html
  har-security-scan capture.har --fail-on high

Auto-generated filename format:
  <hostname>-<UTC timestamp>-har-security-scan.html
`);
  process.exit(0);
}

const inputFile = args[0];
let outputFile  = null;
let failOn      = null;

for (let i = 1; i < args.length; i++) {
  if ((args[i] === '--output' || args[i] === '-o') && args[i + 1]) {
    outputFile = args[++i];
  } else if (args[i] === '--fail-on' && args[i + 1]) {
    failOn = args[++i].toLowerCase();
  }
}

function utcTimestamp() {
  return new Date().toISOString().replace(/\D/g, '').slice(0, 14);
}

function targetHostname(entries) {
  if (!entries.length) return 'scan';
  try { return new URL(entries[0].request.url).hostname; } catch { return 'scan'; }
}

if (!fs.existsSync(inputFile)) {
  console.error(`Error: file not found: ${inputFile}`);
  process.exit(1);
}

let raw;
try {
  raw = JSON.parse(fs.readFileSync(inputFile, 'utf8'));
} catch (e) {
  console.error(`Error: could not parse JSON: ${e.message}`);
  process.exit(1);
}

let har;
try {
  har = parseHAR(raw);
} catch (e) {
  console.error(`Error: ${e.message}`);
  process.exit(1);
}

const findings = runAllChecks(har.entries);

if (!outputFile) {
  const host = targetHostname(har.entries);
  outputFile = `${host}-${utcTimestamp()}-har-security-scan.html`;
}

const html = generateReport(har, findings, { filename: path.basename(inputFile) });
fs.writeFileSync(outputFile, html, 'utf8');
console.log(`Report written to: ${path.resolve(outputFile)}`);

if (failOn && SEVERITY_ORDER[failOn] != null) {
  const triggered = findings.some(f => SEVERITY_ORDER[f.severity] >= SEVERITY_ORDER[failOn]);
  if (triggered) {
    console.error(`Exiting with code 1: findings found at severity "${failOn}" or above.`);
    process.exit(1);
  }
}
