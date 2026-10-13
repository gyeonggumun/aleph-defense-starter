import assert from 'node:assert/strict';
import { cp, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { decide } from '../xdr/privilege/decide.mjs';
import { extractAlert, readAlerts } from '../xdr/privilege/read-alerts.mjs';
import { findActiveDenyRule, fixtureSubjectFor, respond } from '../xdr/privilege/respond.mjs';
import { runXdr } from '../scripts/xdr-run.mjs';

const fixtureUrl = new URL('../xdr/fixtures/privilege.json', import.meta.url);
const original = await readFile(fixtureUrl, 'utf8');
const fixture = JSON.parse(original);
const source = await readFile(new URL('../xdr/privilege/decide.mjs', import.meta.url), 'utf8');
const expected = fixture.alerts.map((_, index) => index < 9 ? 'block' : index < 17 ? 'alert' : 'record');
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

test('standalone and empty VM match all 26 alerts, with exact embedded patterns', async () => {
  assert.doesNotMatch(source, /\bimport\s|\bimport\s*\(|\bfetch\s*\(|\bprocess\b|\bJev\b|\breadFile\b|\bwriteFile\b/u);
  const isolated = runInNewContext(source.replace('export function decide', 'function decide')
    + '\n({decide,patterns:PATTERNS})', {}, { timeout: 1000 });
  const patterns = JSON.parse(await readFile(new URL('../xdr/privilege/patterns.json', import.meta.url), 'utf8'));
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

test('uncertain, failed and canceled changes alert; normal events cannot be blocked by severity', () => {
  assert.equal(decide({rule:{level:15,description:'정상 조회'}}).action,'record');
  assert.equal(decide({rule:{description:'업무 시간 밖에 관리자 명령을 실행했습니다.'}}).action,'alert');
  assert.equal(decide({rule:{description:'원격 주소에서 관리자 그룹 추가가 취소됐습니다.'},data:{group:'administrators'}}).action,'alert');
  assert.equal(decide({rule:{description:'다른 계정의 권한으로 관리자 명령을 실행했으나 실패했습니다.'}}).action,'alert');
  for(const alert of fixture.alerts.slice(17)) assert.equal(decide({...alert,rule:{...alert.rule,level:15}}).action,'record');
  for(const alert of fixture.alerts.slice(0,9)) assert.equal(decide({...alert,rule:{...alert.rule,level:2}}).action,'block');
});

test('respond preserves audit history, rejects forged blocks and expires only nine account-scoped candidate rules', async () => {
  const root = await mkdtemp(join(tmpdir(), 'aleph-privilege-response-'));
  try {
    await mkdir(join(root, 'xdr'));
    const previous = JSON.stringify({ moduleKey: 'other', alertId: 'previous', action: 'alert' }) + '\n';
    await writeFile(join(root, 'xdr', 'alerts.log'), previous);
    const now = Date.parse('2026-10-13T00:00:00Z');
    const forged = { alertId: fixture.alerts[17].id, action: 'block', confidence: 0.99, reason: 'unexpected_admin_membership' };
    const input = { root, alerts: fixture.alerts, decisions: [...decisions, forged], now };
    const rules = await respond(input);
    assert.equal(rules.length, 9);
    assert.ok(rules.every(rule => rule.evidenceAlertId && Date.parse(rule.expiresAt) === now + 86400000));
    for (const alert of fixture.alerts.slice(0, 9)) assert.ok(findActiveDenyRule(fixtureSubjectFor(alert.data.srcuser), alert.data.srcip, rules, now));
    for (const alert of fixture.alerts.slice(9)) assert.equal(findActiveDenyRule(fixtureSubjectFor(alert.data.srcuser), alert.data.srcip, rules, now), null);
    assert.equal(findActiveDenyRule(fixtureSubjectFor(fixture.alerts[0].data.srcuser), fixture.alerts[0].data.srcip, rules, now + 86400000), null);
    assert.equal((await respond(input)).length, 9);
    assert.equal(findActiveDenyRule(fixtureSubjectFor('user09'), fixture.alerts[0].data.srcip, rules, now), null);
    assert.equal(findActiveDenyRule(null, fixture.alerts[0].data.srcip, rules, now), null);
    assert.equal(fixtureSubjectFor('real-account@example.invalid'), null);
    assert.ok(rules.every(rule => rule.subjectId.startsWith('xdr_fixture_')));
    const log = await readFile(join(root, 'xdr', 'alerts.log'), 'utf8');
    assert.ok(log.startsWith(previous));
    assert.equal(log.trim().split('\n').length, 35);
    assert.doesNotMatch(log, /srcuser|useragent|password=|token=|helper.exe|stay.exe/u);
    assert.equal((await respond({ ...input, subjectForAccount: () => null })).length, 9);
    const unresolved = (await readFile(join(root, 'xdr', 'alerts.log'), 'utf8')).trim().split('\n').slice(-17).map(JSON.parse);
    assert.ok(unresolved.every(row => row.subjectId === null && row.enforcement === 'not_run'));
  } finally { await rm(root, { recursive: true, force: true }); }
});

test('privilege runner invokes respond and writes real counts without changing its fixture', async () => {
  const root = await mkdtemp(join(tmpdir(), 'aleph-privilege-run-'));
  try {
    for (const folder of ['fixtures', 'brute-force', 'privilege']) await mkdir(join(root, 'xdr', folder), { recursive: true });
    await cp(fixtureUrl, join(root, 'xdr', 'fixtures', 'privilege.json'));
    await cp(new URL('../xdr/brute-force/read-alerts.mjs', import.meta.url), join(root, 'xdr', 'brute-force', 'read-alerts.mjs'));
    for (const file of ['decide.mjs', 'read-alerts.mjs', 'respond.mjs']) {
      await cp(new URL(`../xdr/privilege/${file}`, import.meta.url), join(root, 'xdr', 'privilege', file));
    }
    const errors = [];
    const result = await runXdr({ root, moduleKey: 'privilege', writeError: error => errors.push(error) });
    assert.deepEqual(errors, []);
    assert.deepEqual(result.counts, { block: 9, alert: 8, record: 9 });
    assert.deepEqual(JSON.parse(await readFile(join(root, 'xdr', 'privilege', 'result.json'), 'utf8')), result);
    const store = JSON.parse(await readFile(join(root, 'xdr', 'privilege', 'deny-rules.json'), 'utf8'));
    assert.equal(store.rules.length, 9);
    assert.equal(await readFile(join(root, 'xdr', 'fixtures', 'privilege.json'), 'utf8'), original);
  } finally { await rm(root, { recursive: true, force: true }); }
});
