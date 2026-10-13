import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import test from 'node:test';
import { fixtureRequests } from '../scripts/fixture-7.mjs';
import { decide as localDecide } from '../src/decider.mjs';

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
