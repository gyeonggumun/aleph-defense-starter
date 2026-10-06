import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import { createAuthProxy } from '../src/auth-proxy.mjs';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 5,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  originalApiUrl: 'https://data.example.supabase.co/rest/v1/vault_notes',
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
    originalApiUrl: config.originalApiUrl,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
  assert.throws(() => deploymentIdentity(env, { ...config, originalApiUrl: undefined }));
  assert.throws(() => deploymentIdentity(env, {
    ...config, originalApiUrl: `${config.originalApiUrl}?select=*`,
  }));
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
        originalApiUrl: config.originalApiUrl,
      }), { status: 200, headers: { 'content-type': 'application/json' } });
      return new Response('ok', { status: 200, headers: { 'X-Content-Type-Options': 'nosniff' } });
    };
    const results = await runAttackChecks(config);
    assert.equal(results.length, 5);
    assert.match(results[0].observed, /HTTP 401/u);
    assert.match(results[2].observed, /\/aleph\.json에서/u);
    assert.match(results[4].observed, /API 키 없음/u);
    assert.deepEqual(requested.map(item => item.path), ['/api/notes', '/data.json', '/aleph.json', '/']);
    assert.equal(requested[0].init.redirect, 'error');
    assert.equal(requested[0].init.headers?.Authorization, undefined);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

function responseStub() {
  return {
    headers: {}, statusCode: 0, payload: null,
    setHeader(name, value) { this.headers[name.toLowerCase()] = value; },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.payload = value; return this; },
    send(value) { this.payload = value; return this; },
  };
}

const authProxyConfig = {
  identityProvider: { issuer: 'https://student.supabase.co/auth/v1' },
};
const authProxyEnv = {
  SUPABASE_URL: 'https://student.supabase.co',
  SUPABASE_SECRET_KEY: 'server-secret-test-key',
};

test('browser keeps Auth SDK calls but ships no Supabase API key', async () => {
  const source = await readFile(new URL('../public/index.html', import.meta.url), 'utf8');
  assert.doesNotMatch(source, /sb_(?:publishable|secret)_[A-Za-z0-9_-]+/iu);
  assert.match(source, /supabase\.auth\.signInWithPassword/u);
  assert.match(source, /supabase\.auth\.signOut/u);
  assert.match(source, /new URL\('\/api\/auth'/u);
});

test('auth proxy sends password login to Supabase with the server-only API key', async () => {
  let outgoing;
  const proxy = createAuthProxy({ config: authProxyConfig, env: authProxyEnv,
    fetchImpl: async (url, init) => {
      outgoing = { url: new URL(url), init };
      return new Response(JSON.stringify({ access_token: 'test.access.token' }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
    } });
  const response = responseStub();
  await proxy({ method: 'POST', query: { path: 'token', grant_type: 'password' },
    headers: { authorization: 'Bearer server-auth-proxy' },
    body: { email: 'a@example.test', password: 'example-password', extra: 'discarded' },
  }, response);
  assert.equal(outgoing.url.href, 'https://student.supabase.co/auth/v1/token?grant_type=password');
  assert.equal(outgoing.init.headers.get('apikey'), authProxyEnv.SUPABASE_SECRET_KEY);
  assert.equal(outgoing.init.headers.get('authorization'), null);
  assert.deepEqual(JSON.parse(outgoing.init.body), {
    email: 'a@example.test', password: 'example-password',
  });
  assert.equal(response.statusCode, 200);
  assert.equal(response.headers['cache-control'], 'no-store');
});

test('auth proxy forwards only a signed-in JWT for logout and rejects non-Auth routes', async () => {
  let outgoing;
  let calls = 0;
  const proxy = createAuthProxy({ config: authProxyConfig, env: authProxyEnv,
    fetchImpl: async (url, init) => {
      calls += 1;
      outgoing = { url: new URL(url), init };
      return new Response(null, { status: 204 });
    } });
  const jwt = 'header.payload.signature';
  const logoutResponse = responseStub();
  await proxy({ method: 'POST', query: { path: 'logout', scope: 'global' },
    headers: { authorization: `Bearer ${jwt}` }, body: undefined,
  }, logoutResponse);
  assert.equal(outgoing.url.href, 'https://student.supabase.co/auth/v1/logout?scope=global');
  assert.equal(outgoing.init.headers.get('apikey'), authProxyEnv.SUPABASE_SECRET_KEY);
  assert.equal(outgoing.init.headers.get('authorization'), `Bearer ${jwt}`);
  assert.equal(logoutResponse.statusCode, 204);

  const deniedResponse = responseStub();
  await proxy({ method: 'GET', query: { path: 'rest/v1/vault_notes' }, headers: {} }, deniedResponse);
  assert.equal(deniedResponse.statusCode, 404);
  assert.equal(calls, 1);
});
