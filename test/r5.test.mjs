import assert from 'node:assert/strict';
import { test } from 'node:test';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 5,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  repoUrl: 'https://github.com/student-a/aleph-defense',
  publicAppUrl: 'https://student-defense.vercel.app',
};
const env = {
  VERCEL_GIT_PROVIDER: 'github',
  VERCEL_GIT_REPO_OWNER: 'Student-A',
  VERCEL_GIT_REPO_SLUG: 'aleph-defense',
  VERCEL_GIT_COMMIT_SHA: 'a'.repeat(40),
  VERCEL_URL: 'student-defense-123.vercel.app',
};

test('build identity uses Vercel Git and deployment metadata', () => {
  assert.deepEqual(deploymentIdentity(env, config), {
    schema: 'aleph.defense.deployment.v1',
    step: 5,
    repoUrl: 'https://github.com/student-a/aleph-defense',
    commit: 'a'.repeat(40),
    publicAppUrl: 'https://student-defense-123.vercel.app',
    judgeIssuer: config.judgeIssuer,
    sampleMarker: config.sampleMarker,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
});

test('stage 5 self-check records unauthenticated denial and deployment protections', async () => {
  const originalFetch = globalThis.fetch;
  const requested = [];
  try {
    globalThis.fetch = async (url, init) => {
      const parsed = new URL(String(url));
      requested.push({ path: parsed.pathname, init });
      if (parsed.pathname === '/api/notes') return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
        status: 401, headers: { 'content-type': 'application/json' },
      });
      if (parsed.pathname === '/data.json') return new Response(JSON.stringify({ notes: [] }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
      if (parsed.pathname === '/aleph.json') return new Response(JSON.stringify({
        schema: 'aleph.defense.deployment.v1', step: 5, repoUrl: config.repoUrl,
        commit: 'a'.repeat(40), publicAppUrl: 'https://student-defense-123.vercel.app',
      }), { status: 200, headers: { 'content-type': 'application/json' } });
      return new Response('ok', { status: 200, headers: { 'X-Content-Type-Options': 'nosniff' } });
    };
    const results = await runAttackChecks(config);
    assert.equal(results.length, 4);
    assert.match(results[0].observed, /HTTP 401/u);
    assert.match(results[2].observed, /\/aleph\.json에서/u);
    assert.deepEqual(requested.map(item => item.path), ['/api/notes', '/data.json', '/aleph.json', '/']);
    assert.equal(requested[0].init.redirect, 'error');
    assert.equal(requested[0].init.headers?.Authorization, undefined);
  } finally {
    globalThis.fetch = originalFetch;
  }
});
