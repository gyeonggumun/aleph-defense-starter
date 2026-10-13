import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide as localDecide, RULE_IDS } from '../src/decider.mjs';

const source = readFileSync(new URL('../src/decider.mjs', import.meta.url), 'utf8');
const standalone = await import('data:text/javascript;base64,' + Buffer.from(source).toString('base64'));
const isolated = runInNewContext(
  source.replace(/\bexport (?=(?:async )?function|const)/gu, '') + '\n;({ decide });',
  {}, { timeout: 1000 },
);

for (const [name, decide] of [['로컬 모듈', localDecide], ['단독 파일', standalone.decide], ['격리 VM', isolated.decide]]) {
  test(name + ': 등록만 허용하고 누락·문자열·위조 헤더를 거부', async () => {
    const { normal, suspicious } = fixtureRequests();
    for (const path of [normal.path, '/notes/demo']) {
      const result = await decide({ ...normal, path });
      assert.equal(result.decision, 'allow');
      assert.equal(result.reasonCode, 'approved');
      assert.ok(result.ruleIds.includes('device_registered'));
    }
    for (const deviceRegistered of [false, undefined, null, 'true', 1]) {
      const result = await decide({ ...normal, deviceRegistered,
        headers: { 'x-device-registered': 'true' }, device: { registered: true } });
      assert.equal(result.decision, 'deny');
      assert.equal(result.reasonCode, 'device_not_registered');
      assert.ok(result.ruleIds.includes('device_registered'));
      assert.equal(Object.keys(result).sort().join(','),
        'decision,reasonCode,requestId,ruleIds,schema');
    }
    assert.equal((await decide(suspicious)).decision, 'step_up');
    assert.equal((await decide({ ...normal, path: '/notes/export' })).decision, 'deny');
  });
}

test('단독 실행에서 로컬 XDR 저장소가 필요하면 허용으로 우회하지 않음', async () => {
  const { normal } = fixtureRequests();
  const result = await standalone.decide({ ...normal, signals: { source: '192.0.2.1' } });
  assert.equal(result.decision, 'deny');
});

test('12단계 가점: 계약 항목만 읽고 모든 정상·금지 응답과 규칙 ID가 유효함', async () => {
  const allowedFields = new Set(['schema', 'requestId', 'classId', 'projectId', 'subjectId',
    'deviceId', 'service', 'method', 'path', 'route', 'queryLength', 'querySha256', 'at',
    'policyRevision', 'deviceRegistered', 'stepUp', 'recentEvents', 'signals']);
  const { normal, suspicious } = fixtureRequests();
  const requests = [normal, suspicious, { ...normal, deviceRegistered: false },
    { ...normal, deviceRegistered: undefined }, { ...normal, service: 'unknown' },
    { ...normal, method: 'PUT' }, { ...normal, queryLength: 3 },
    { ...normal, path: '/api/notes/export', route: 'GET /api/notes/:id' },
    { ...normal, path: '/api/notices/demo', method: 'PUT', route: 'PUT /api/notices/:id' },
    { ...suspicious, stepUp: { verified: true, authAgeSeconds: 60 } }];
  for (const request of requests) {
    const guarded = new Proxy(request, { get(target, name) {
      assert.ok(allowedFields.has(name), `문서 밖 요청 항목 접근: ${String(name)}`);
      return Reflect.get(target, name);
    } });
    const result = await localDecide(guarded);
    assert.equal(Object.keys(result).sort().join(','), 'decision,reasonCode,requestId,ruleIds,schema');
    assert.equal(result.schema, 'aleph.decision.v1');
    assert.equal(result.requestId, request.requestId);
    assert.ok(['allow', 'deny', 'step_up'].includes(result.decision));
    assert.ok(result.ruleIds.every(id => RULE_IDS.includes(id)));
  }
  const config = JSON.parse(readFileSync(new URL('../aleph.config.json', import.meta.url), 'utf8'));
  assert.ok(config.step >= 12);
});
