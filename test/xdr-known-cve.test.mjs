import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { decide } from '../xdr/known-cve/decide.mjs';
import { extractAlert, readAlerts } from '../xdr/known-cve/read-alerts.mjs';
import { findActiveDenyRule, respond } from '../xdr/known-cve/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const fixtureUrl = new URL('../xdr/fixtures/known-cve.json', import.meta.url);
const original = await readFile(fixtureUrl, 'utf8');
const fixture = JSON.parse(original);
const source = await readFile(new URL('../xdr/known-cve/decide.mjs', import.meta.url), 'utf8');
const expected = fixture.alerts.map((_, index) => index < 8 ? 'block' : index < 16 ? 'alert' : 'record');
const decisions = fixture.alerts.map(alert => ({ alertId: alert.id, ...decide(alert) }));

test('reader emits one safe five-field row per original alert', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, fixture.alerts.length);
  assert.ok(rows.every(row => Object.keys(row).join(',') === 'timestamp,sourceAddress,account,ruleLevel,description'));
  // Synthetic secrets for redaction tests, never real credentials.
  const safe = extractAlert({ timestamp: '2026-10-01T00:00:00Z', data: {
    srcip: '192.0.2.1', srcuser: 'token=reader-fixture-secret' },
    rule: { level: 5, description: 'password=reader-fixture-password client_secret=reader-fixture-client' } });
  assert.doesNotMatch(JSON.stringify(safe), /reader-fixture/u);
  const partial = extractAlert({ description: '-----BEGIN PRIVATE KEY-----\nreader-fixture-private' });
  assert.doesNotMatch(partial.description, /PRIVATE KEY|reader-fixture/u);
  assert.equal(await readFile(fixtureUrl, 'utf8'), original);
});

test('standalone and empty VM match all 24 alerts, with exact embedded patterns', async () => {
  assert.doesNotMatch(source, /\bimport\s|\bimport\s*\(|\bfetch\s*\(|\bprocess\b|\bJev\b|\breadFile\b|\bwriteFile\b/u);
  const isolated = runInNewContext(source.replace('export function decide', 'function decide')
    + '\n({decide,patterns:PATTERNS})', {}, { timeout: 1000 });
  const patterns = JSON.parse(await readFile(new URL('../xdr/known-cve/patterns.json', import.meta.url), 'utf8'));
  assert.deepEqual(JSON.parse(JSON.stringify(isolated.patterns)), patterns.patterns);
  assert.ok(patterns.patterns.every(pattern => pattern.name && pattern.condition && pattern.evidence && !pattern.evidence.includes('\n')));
  const standalone = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  assert.deepEqual(Object.keys(standalone), ['decide']);
  for (const fn of [decide, isolated.decide, standalone.decide]) {
    const results = fixture.alerts.map(fn);
    assert.deepEqual(results.map(result => result.action), expected);
    assert.ok(results.every(result => Object.keys(result).join(',') === 'action,confidence,reason'
      && result.confidence >= 0 && result.confidence <= 1 && !result.reason.includes('\n')));
    assert.deepEqual(fixture.alerts.map(alert => fn({ ...alert, id: 'changed-id' }).action), expected);
  }
});

test('names, scanner clues and truncated lookups alert; severity alone cannot block', () => {
  assert.equal(decide({ rule: { level: 15, description: '정상 조회' }, data: { url: '/notes' } }).action, 'record');
  assert.equal(decide({ rule: { level: 15, description: 'CVE-2021-44228 문서' }, data: { url: '/docs' } }).action, 'alert');
  assert.equal(decide({ data: { useragent: 'nuclei' } }).action, 'alert');
  assert.equal(decide({ data: { url: '/search?x=${jndi:ldap:' } }).action, 'alert');
  const first = fixture.alerts[0];
  assert.equal(decide({ ...first, data: { ...first.data, useragent: encodeURIComponent(first.data.useragent) } }).action, 'block');
  assert.equal(decide({ ...first, data: { url: '/' } }).action, 'alert');
});

test('respond preserves audit history, rejects forged blocks and expires only eight candidate rules', async () => {
  const root = await mkdtemp(join(tmpdir(), 'aleph-known-cve-response-'));
  try {
    await mkdir(join(root, 'xdr'));
    const previous = JSON.stringify({ moduleKey: 'other', alertId: 'previous', action: 'alert' }) + '\n';
    await writeFile(join(root, 'xdr', 'alerts.log'), previous);
    const now = Date.parse('2026-10-13T00:00:00Z');
    const forged = { alertId: fixture.alerts[16].id, action: 'block', confidence: 0.99, reason: 'log4shell_remote_lookup' };
    const input = { root, alerts: fixture.alerts, decisions: [...decisions, forged], now };
    const rules = await respond(input);
    assert.equal(rules.length, 8);
    assert.ok(rules.every(rule => rule.evidenceAlertId && Date.parse(rule.expiresAt) === now + 86400000));
    for (const alert of fixture.alerts.slice(0, 8)) assert.ok(findActiveDenyRule(alert.data.srcip, rules, now));
    for (const alert of fixture.alerts.slice(8)) assert.equal(findActiveDenyRule(alert.data.srcip, rules, now), null);
    assert.equal(findActiveDenyRule(fixture.alerts[0].data.srcip, rules, now + 86400000), null);
    assert.equal((await respond(input)).length, 8);
    const log = await readFile(join(root, 'xdr', 'alerts.log'), 'utf8');
    assert.ok(log.startsWith(previous));
    assert.equal(log.trim().split('\n').length, 33);
    assert.doesNotMatch(log, /jndi:|srcuser|useragent|password=|token=/u);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('known-cve runner invokes respond and writes real counts without changing its fixture', async () => {
  const root = await mkdtemp(join(tmpdir(), 'aleph-known-cve-run-'));
  try {
    for (const folder of ['fixtures', 'brute-force', 'known-cve']) await mkdir(join(root, 'xdr', folder), { recursive: true });
    await cp(fixtureUrl, join(root, 'xdr', 'fixtures', 'known-cve.json'));
    await cp(new URL('../xdr/brute-force/read-alerts.mjs', import.meta.url), join(root, 'xdr', 'brute-force', 'read-alerts.mjs'));
    for (const file of ['decide.mjs', 'read-alerts.mjs', 'respond.mjs']) {
      await cp(new URL(`../xdr/known-cve/${file}`, import.meta.url), join(root, 'xdr', 'known-cve', file));
    }
    const errors = [];
    const result = await runXdr({ root, moduleKey: 'known-cve', writeError: error => errors.push(error) });
    assert.deepEqual(errors, []);
    assert.deepEqual(result.counts, { block: 8, alert: 8, record: 8 });
    assert.deepEqual(JSON.parse(await readFile(join(root, 'xdr', 'known-cve', 'result.json'), 'utf8')), result);
    const store = JSON.parse(await readFile(join(root, 'xdr', 'known-cve', 'deny-rules.json'), 'utf8'));
    assert.equal(store.rules.length, 8);
    assert.equal(await readFile(join(root, 'xdr', 'fixtures', 'known-cve.json'), 'utf8'), original);
  } finally { await rm(root, { recursive: true, force: true }); }
});
