import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { runInNewContext } from 'node:vm';
import { test } from 'node:test';

const source = readFileSync(new URL('../xdr/brute-force/decide.mjs', import.meta.url), 'utf8');
const fixture = JSON.parse(readFileSync(new URL('../xdr/fixtures/brute-force.json', import.meta.url), 'utf8'));
const expected = { block: 10, alert: 9, record: 9 };

function summarize(results) {
  return results.reduce((counts, result) => {
    counts[result.action] += 1;
    assert.ok(Number.isFinite(result.confidence));
    assert.equal(typeof result.reason, 'string');
    return counts;
  }, { block: 0, alert: 0, record: 0 });
}

test('brute-force decide runs as a standalone module with the expected decisions', async () => {
  const module = await import(`data:text/javascript;base64,${Buffer.from(source).toString('base64')}`);
  const results = await Promise.all(fixture.alerts.map(module.decide));
  assert.deepEqual(summarize(results), expected);
  for (let index = 19; index < results.length; index += 1) {
    assert.notEqual(results[index].action, 'block');
  }
});

test('brute-force decide executes in an isolated context without process or imports', async () => {
  const decide = runInNewContext(
    source.replace('export async function decide', 'async function decide') + '\n;decide;',
    {}, { timeout: 1000 },
  );
  const results = [];
  for (const alert of fixture.alerts) results.push(await decide(alert));
  assert.deepEqual(summarize(results), expected);
});
