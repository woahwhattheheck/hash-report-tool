'use strict';

// Focused, offline regression of the EXACT exported browser helper functions.
// Does not run the whole application, fetch network data or hash real evidence.
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const html = fs.readFileSync(path.join(__dirname, '..', 'index.html'), 'utf8');
function extract(startMarker, endMarker) {
  const start = html.indexOf(startMarker);
  const end = start < 0 ? -1 : html.indexOf(endMarker, start);
  assert(start >= 0 && end > start, 'source helper boundary exists');
  return html.slice(start, end);
}

const parseEml = vm.runInNewContext(
  extract('function parseEml(text) {', '// ===== GENERATE EMAIL FORENSIC PDF') +
    '\nparseEml;'
);

const headerOnly = [
  'From: Clinic <vet@example.test>',
  'Subject: Without body separator',
  'Received: from mx [192.0.2.8]',
  'DKIM-Signature: v=1; a=rsa-sha256;',
].join('\r\n');
const solo = parseEml(headerOnly);
assert.equal(solo.from, 'Clinic <vet@example.test>');
assert.equal(solo.subject, 'Without body separator');
assert.equal(solo.serverIP, '192.0.2.8');
assert.equal(solo.dkim, 'PRESENT (NOT VERIFIED)');
assert.equal(solo.bodyPreview, 'No body content');

// Lookalike body lines are never promoted into forensic headers.
const spoofed = parseEml(
  'From: Original <owner@example.test>\r\nSubject: Real\r\n\r\n' +
  'From: Forged <attacker@example.test>\r\nDKIM-Signature: fake'
);
assert.equal(spoofed.from, 'Original <owner@example.test>');
assert.equal(spoofed.subject, 'Real');
assert.equal(spoofed.dkim, 'NOT PRESENT');

const events = [];
const timers = [];
const anchor = {
  href: '', download: '',
  click() { events.push('click'); },
  remove() { events.push('remove'); },
};
const sandbox = {
  Blob: class MockBlob {
    constructor(parts, options) { this.parts = parts; this.type = options.type; }
  },
  URL: {
    createObjectURL() { events.push('url-created'); return 'blob:forensic-csv'; },
    revokeObjectURL(url) { events.push('url-revoked:' + url); },
  },
  document: {
    createElement(tag) { assert.equal(tag, 'a'); return anchor; },
    body: { appendChild(node) { assert.equal(node, anchor); events.push('attached'); } },
  },
  setTimeout(fn, ms) { timers.push({ fn, ms }); },
};
const { downloadBlobFile, downloadCsvFile } = vm.runInNewContext(
  extract('function downloadBlobFile(blob, filename) {', 'function downloadSelectedCSV() {') +
    '\n({ downloadBlobFile, downloadCsvFile });', sandbox
);
downloadCsvFile('"SHA-3-256","abc"\r\n', 'Hash_Report.csv');
assert.equal(anchor.href, 'blob:forensic-csv');
assert.equal(anchor.download, 'Hash_Report.csv');
assert.deepEqual(events, ['url-created', 'attached', 'click', 'remove']);
assert.equal(timers.length, 1);
assert.equal(timers[0].ms, 30000);
timers[0].fn();
assert.equal(events.at(-1), 'url-revoked:blob:forensic-csv');

// Word export delegates to the same tested browser-safe blob lifecycle.
assert.match(html, /downloadBlobFile\(blob, "Hash_Report\.docx"\);/);
events.length = 0;
timers.length = 0;
downloadBlobFile(
  new sandbox.Blob(['docx'], {
    type: 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  }),
  'Hash_Report.docx'
);
assert.equal(anchor.href, 'blob:forensic-csv');
assert.equal(anchor.download, 'Hash_Report.docx');
assert.deepEqual(events, ['url-created', 'attached', 'click', 'remove']);
assert.equal(timers.length, 1);
assert.equal(timers[0].ms, 30000);
timers[0].fn();
assert.equal(events.at(-1), 'url-revoked:blob:forensic-csv');

console.log('Focused header-only EML + shared CSV/DOCX blob lifecycle checks passed');
