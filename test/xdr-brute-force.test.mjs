import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { applyActions } from '../xdr/brute-force/apply-actions.mjs';
import { decide } from '../xdr/brute-force/decide.mjs';
import { extractAlert, readAlerts } from '../xdr/brute-force/read-alerts.mjs';
import { findActiveDenyRule } from '../xdr/brute-force/ztna-rules.mjs';

test('Wazuh reader returns one redacted, allowlisted row per fixture alert', async () => {
  const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
  const alerts = await readAlerts();
  assert.equal(alerts.length, fixture.alerts.length);
  assert.ok(alerts.every(alert => Object.keys(alert).join(',')
    === 'timestamp,sourceAddress,account,ruleLevel,description'));
  assert.equal(alerts[0].sourceAddress, '203.0.113.10');
  assert.deepEqual(extractAlert(alerts[0]), alerts[0]);

  const sanitized = extractAlert({ timestamp: '2026-10-07T00:00:00Z',
    data: { srcip: '203.0.113.20', srcuser: 'user01' },
    rule: { level: 8, description: 'login failed token=must-not-appear' },
  });
  assert.doesNotMatch(JSON.stringify(sanitized), /must-not-appear/u);
  assert.equal(sanitized.ruleLevel, 8);
});

test('decisions and temporary ZTNA rules block only the ten clear fixture attacks', async () => {
  const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
  const outcomes = await Promise.all(fixture.alerts.map(decide));
  const counts = outcomes.reduce((all, item) => ({ ...all, [item.action]: all[item.action] + 1 }),
    { block: 0, alert: 0, record: 0 });
  assert.deepEqual(counts, { block: 10, alert: 9, record: 9 });
  const root = await mkdtemp(join(tmpdir(), 'xdr-brute-force-'));
  try {
    const now = Date.parse('2026-10-07T00:00:00Z');
    const decisions = outcomes.map((item, index) => ({ ...item, alertId: fixture.alerts[index].id }));
    const rules = await applyActions({ root, alerts: fixture.alerts, decisions, now });
    const blockedIds = new Set(decisions.filter(item => item.action === 'block').map(item => item.alertId));
    assert.equal(rules.length, 10);
    assert.ok(rules.every(rule => blockedIds.has(rule.evidenceAlertId)));
    assert.ok(rules.every(rule => Date.parse(rule.expiresAt) > now));
    const persisted = JSON.parse(await readFile(join(root, 'xdr', 'brute-force', 'deny-rules.json'), 'utf8'));
    assert.equal(persisted.rules.length, 10);
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});

test('temporary deny rule matches only the same valid address before expiry', () => {
  const now = Date.parse('2026-10-07T00:00:00Z');
  const rules = [{ ruleId: 'xdr.brute_force_source_ip', sourceAddress: '203.0.113.10',
    alertId: 'bf-01', expiresAt: '2026-10-07T00:15:00Z' }];
  assert.equal(findActiveDenyRule('203.0.113.10', rules, now), rules[0]);
  assert.equal(findActiveDenyRule('203.0.113.11', rules, now), null);
  assert.equal(findActiveDenyRule('not-an-ip', rules, now), null);
  assert.equal(findActiveDenyRule('203.0.113.10', rules, Date.parse('2026-10-07T00:15:00Z')), null);
});
