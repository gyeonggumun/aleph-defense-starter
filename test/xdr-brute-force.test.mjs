import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { extractAlert, readAlerts } from '../xdr/brute-force/read-alerts.mjs';
import { findActiveDenyRule } from '../xdr/brute-force/ztna-rules.mjs';

test('Wazuh reader returns one redacted, allowlisted row per fixture alert', async () => {
  const fixture = JSON.parse(await readFile(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
  const alerts = await readAlerts();
  assert.equal(alerts.length, fixture.alerts.length);
  assert.ok(alerts.every(alert => Object.keys(alert).join(',')
    === 'timestamp,sourceAddress,account,ruleLevel,description'));
  assert.equal(alerts[0].sourceAddress, '203.0.113.10');

  const sanitized = extractAlert({ timestamp: '2026-10-07T00:00:00Z',
    data: { srcip: '203.0.113.20', srcuser: 'user01' },
    rule: { level: 8, description: 'login failed token=must-not-appear' },
  });
  assert.doesNotMatch(JSON.stringify(sanitized), /must-not-appear/u);
  assert.equal(sanitized.ruleLevel, 8);
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
