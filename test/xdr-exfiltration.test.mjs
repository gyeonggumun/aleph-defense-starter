import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { decide } from '../xdr/exfiltration/decide.mjs';
import { extractAlert, readAlerts } from '../xdr/exfiltration/read-alerts.mjs';
import { findActiveDenyRule, decideTransfer, respond } from '../xdr/exfiltration/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const fixtureUrl = new URL('../xdr/fixtures/exfiltration.json', import.meta.url);
const original = await readFile(fixtureUrl, 'utf8');
const fixture = JSON.parse(original);
const source = await readFile(new URL('../xdr/exfiltration/decide.mjs', import.meta.url), 'utf8');
const expected = fixture.alerts.map((_, index) => index < 10 ? 'block' : index < 20 ? 'alert' : 'record');
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

test('standalone and empty VM match all 30 alerts, with exact embedded patterns', async () => {
  assert.doesNotMatch(source, /\bimport\s|\bimport\s*\(|\bfetch\s*\(|\bprocess\b|\bJev\b|\breadFile\b|\bwriteFile\b/u);
  const isolated = runInNewContext(source.replace('export function decide', 'function decide')
    + '\n({decide,patterns:PATTERNS})', {}, { timeout: 1000 });
  const patterns = JSON.parse(await readFile(new URL('../xdr/exfiltration/patterns.json', import.meta.url), 'utf8'));
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

test('large bytes, time or severity alone do not block; failed and missing transfers only alert', () => {
 assert.equal(decide({rule:{level:15,description:'정상 조회'}}).action,'record');
 assert.equal(decide({rule:{description:'업무 시간 밖에 전송 1건'},data:{dstip:'192.0.2.90',bytes:'2400'}}).action,'alert');
 assert.equal(decide({rule:{description:'대용량 파일 전송'},data:{dstip:'192.0.2.90',bytes:'100000000'}}).action,'alert');
 const first=fixture.alerts[0];
 assert.equal(decide({...first,data:{...first.data,bytes:'0'}}).action,'alert');
 assert.equal(decide({...first,data:{...first.data,dstip:undefined}}).action,'alert');
 assert.equal(decide({...first,rule:{description:'처음 보는 목적지로 큰 파일 전송이 실패했습니다.'}}).action,'alert');
 for(const alert of fixture.alerts.slice(20))assert.equal(decide({...alert,rule:{...alert.rule,level:15}}).action,'record');
 for(const alert of fixture.alerts.slice(0,10))assert.equal(decide({...alert,rule:{...alert.rule,level:2}}).action,'block');
});

test('respond preserves audit history, rejects forged blocks and expires only ten destination candidate rules', async () => {
  const root = await mkdtemp(join(tmpdir(), 'aleph-exfiltration-response-'));
  try {
    await mkdir(join(root, 'xdr'));
    const previous = JSON.stringify({ moduleKey: 'other', alertId: 'previous', action: 'alert' }) + '\n';
    await writeFile(join(root, 'xdr', 'alerts.log'), previous);
    const now = Date.parse('2026-10-13T00:00:00Z');
    const forged = { alertId: fixture.alerts[20].id, action: 'block', confidence: 0.99, reason: 'large_unfamiliar_transfer' };
    const input = { root, alerts: fixture.alerts, decisions: [...decisions, forged], now };
    const rules = await respond(input);
    assert.equal(rules.length, 10);
    assert.ok(rules.every(rule => rule.evidenceAlertId && Date.parse(rule.expiresAt) === now + 86400000));
    for (const alert of fixture.alerts.slice(0, 10)) assert.ok(findActiveDenyRule(alert.data.dstip, rules, now));
    for (const alert of fixture.alerts.slice(10)) assert.equal(findActiveDenyRule(alert.data.dstip, rules, now), null);
    assert.equal(findActiveDenyRule(fixture.alerts[0].data.dstip, rules, now + 86400000), null);
    assert.equal((await respond(input)).length, 10);
    for (const alert of fixture.alerts) assert.equal(findActiveDenyRule(alert.data.srcip, rules, now), null);
    const { fixtureRequests } = await import('../scripts/fixture-7.mjs');
    for(const [i,alert] of fixture.alerts.entries()) {
      if (!alert.data.dstip) continue;
      const { normal } = fixtureRequests();
      const result = await decideTransfer({request:normal,destinationAddress:alert.data.dstip,root,now});
      assert.equal(result.decision,i<10?'deny':'allow');
    }
    const { normal } = fixtureRequests();
    assert.equal((await decideTransfer({request:normal,destinationAddress:null,root,now})).decision,'deny');
    normal.deviceRegistered=false;
    assert.equal((await decideTransfer({request:normal,destinationAddress:'198.51.100.10',root,now})).reasonCode,'device_not_registered');
    normal.deviceRegistered=true;
    normal.signals.source='judge_fixture';normal.signals.hour=3;normal.signals.network='unusual';
    normal.recentEvents=[{kind:'risk_signal',ageSeconds:60,count:20}];
    assert.equal((await decideTransfer({request:normal,destinationAddress:'198.51.100.10',root,now})).decision,'step_up');
    const log = await readFile(join(root, 'xdr', 'alerts.log'), 'utf8');
    assert.ok(log.startsWith(previous));
    assert.equal(log.trim().split('\n').length, 41);
    assert.doesNotMatch(log, /srcuser|useragent|password=|token=|helper.exe|stay.exe/u);
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('exfiltration runner invokes respond and writes real counts without changing its fixture', async () => {
  const root = await mkdtemp(join(tmpdir(), 'aleph-exfiltration-run-'));
  try {
    for (const folder of ['fixtures', 'brute-force', 'exfiltration']) await mkdir(join(root, 'xdr', folder), { recursive: true });
    await mkdir(join(root, 'src'));
    await cp(new URL('../src/decider.mjs', import.meta.url), join(root, 'src', 'decider.mjs'));
    await cp(fixtureUrl, join(root, 'xdr', 'fixtures', 'exfiltration.json'));
    await cp(new URL('../xdr/brute-force/read-alerts.mjs', import.meta.url), join(root, 'xdr', 'brute-force', 'read-alerts.mjs'));
    for (const file of ['decide.mjs', 'read-alerts.mjs', 'respond.mjs']) {
      await cp(new URL(`../xdr/exfiltration/${file}`, import.meta.url), join(root, 'xdr', 'exfiltration', file));
    }
    const errors = [];
    const result = await runXdr({ root, moduleKey: 'exfiltration', writeError: error => errors.push(error) });
    assert.deepEqual(errors, []);
    assert.deepEqual(result.counts, { block: 10, alert: 10, record: 10 });
    assert.deepEqual(JSON.parse(await readFile(join(root, 'xdr', 'exfiltration', 'result.json'), 'utf8')), result);
    const store = JSON.parse(await readFile(join(root, 'xdr', 'exfiltration', 'deny-rules.json'), 'utf8'));
    assert.equal(store.rules.length, 10);
    assert.equal(await readFile(join(root, 'xdr', 'fixtures', 'exfiltration.json'), 'utf8'), original);
  } finally { await rm(root, { recursive: true, force: true }); }
});
