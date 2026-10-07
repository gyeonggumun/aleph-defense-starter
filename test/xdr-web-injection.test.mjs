import assert from 'node:assert/strict';
import { readFile, mkdtemp, mkdir, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runInNewContext } from 'node:vm';
import { test } from 'node:test';
import { decide } from '../xdr/web-injection/decide.mjs';
import { readAlerts, extractAlert } from '../xdr/web-injection/read-alerts.mjs';
import { applyActions } from '../xdr/web-injection/apply-actions.mjs';
import { findActiveDenyRule } from '../xdr/web-injection/ztna-rules.mjs';

const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/web-injection.json', import.meta.url), 'utf8'));
const source = await readFile(new URL('../xdr/web-injection/decide.mjs', import.meta.url), 'utf8');
const expected = fixture.alerts.map((_, i) => i < 8 ? 'block' : i < 17 ? 'alert' : 'record');

test('raw, redacted and isolated inputs give the same per-event decisions', async () => {
  const rows = await readAlerts();
  assert.equal(rows.length, 26);
  assert.ok(rows.every(row => Object.keys(row).join(',') === 'timestamp,sourceAddress,account,ruleLevel,description'));
  assert.doesNotMatch(JSON.stringify(extractAlert({ rule: { description: 'token=never-output' } })), /never-output/u);
  const isolated = runInNewContext(source.replace('export async function decide', 'async function decide') + '\n;decide;', {}, { timeout: 1000 });
  const standalone = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  for (const [fn, inputs] of [[decide, fixture.alerts], [decide, rows], [isolated, fixture.alerts], [standalone.decide, fixture.alerts]]) {
    const results = await Promise.all(inputs.map(fn));
    assert.deepEqual(results.map(r => r.action), expected);
    assert.ok(results.every(r => r.confidence >= 0 && r.confidence <= 1 && !r.reason.includes('\n')));
  }
});

test('Jev failure alerts; unsubstantiated model confidence cannot block single requests', async () => {
  for (const reviewer of [() => { throw new Error('unavailable'); }, () => ({ confidence: 0.99 }), () => new Promise(() => {})]) {
    const fn = runInNewContext(source.replace('export async function decide', 'async function decide') + '\n;decide;',
      { Jev: { review: reviewer }, setTimeout, clearTimeout }, { timeout: 1000 });
    assert.equal((await fn(fixture.alerts[12])).action, 'alert');
  }
  assert.notEqual((await decide({ ...fixture.alerts[0], data: { srcip: '203.0.113.10', count: 1 } })).action, 'block');
});

test('eight expiring evidence rules, nine alerts and no normal address denied', async () => {
  const root = await mkdtemp(join(tmpdir(), 'xdr-web-injection-'));
  await mkdir(join(root, 'xdr'));
  const previous = JSON.stringify({ alertId: 'bf-existing', action: 'alert' });
  await writeFile(join(root, 'xdr', 'alerts.log'), previous + '\n');
  const decisions = await Promise.all(fixture.alerts.map(async alert => ({ alertId: alert.id, ...await decide(alert) })));
  const now = Date.parse('2026-10-07T00:00:00Z');
  const rules = await applyActions({ root, alerts: fixture.alerts, decisions, now });
  assert.equal(rules.length, 8);
  assert.ok(rules.every(rule => rule.evidenceAlertId && Date.parse(rule.expiresAt) > now));
  for (const alert of fixture.alerts.slice(0, 8)) assert.ok(findActiveDenyRule(alert.data.srcip, rules, now));
  for (const alert of fixture.alerts.slice(8)) assert.equal(findActiveDenyRule(alert.data.srcip, rules, now), null);
  assert.equal(findActiveDenyRule(fixture.alerts[0].data.srcip, rules, now + 86400000), null);
  const log = await readFile(join(root, 'xdr', 'alerts.log'), 'utf8');
  assert.ok(log.includes(previous));
  assert.equal(log.trim().split('\n').length, 18);
  assert.doesNotMatch(log, /doc-sql-chain|srcuser|password=/u);
});
