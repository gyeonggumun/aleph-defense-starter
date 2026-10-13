import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { test } from 'node:test';
import authHandler from '../api/auth.js';
import { createAuthProxy } from '../src/auth-proxy.mjs';
import { deploymentIdentity } from '../scripts/deployment-identity.mjs';
import { getLastCheckEvidence, runAttackChecks } from '../src/attack-check.mjs';

const config = {
  step: 5,
  judgeIssuer: 'https://aleph-judge-production.up.railway.app/defense/judge',
  sampleMarker: 'SAMPLE_NOTE_1',
  originalApiUrl: 'https://data.example.supabase.co/rest/v1/vault_notes',
  allowedRoutes: ['GET /api/notes', 'POST /api/notes', 'GET /api/notes/:id',
    'PUT /api/notes/:id', 'DELETE /api/notes/:id'],
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
    allowedRoutes: config.allowedRoutes,
    originalApiUrl: config.originalApiUrl,
  });
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_PROVIDER: undefined }, config));
  assert.throws(() => deploymentIdentity({ ...env, VERCEL_GIT_COMMIT_SHA: 'short' }, config));
  assert.throws(() => deploymentIdentity(env, { ...config, allowedRoutes: [] }));
  assert.throws(() => deploymentIdentity(env, { ...config, allowedRoutes: ['bad route'] }));
  assert.throws(() => deploymentIdentity(env, { ...config, originalApiUrl: undefined }));
  assert.throws(() => deploymentIdentity(env, {
    ...config, originalApiUrl: `${config.originalApiUrl}?select=*`,
  }));
  assert.throws(() => deploymentIdentity(env, {
    ...config, originalApiUrl: 'https://data.example.supabase.co/',
  }));
});

test('deployment identity accepts exact service-method-path route objects', () => {
  const allowedRoutes = [
    { service: 'notes', method: 'GET', pathPattern: '/api/my/notes' },
    { service: 'notes', method: 'GET', pathPattern: '/api/notes/:id' },
  ];
  assert.deepEqual(deploymentIdentity(env, { ...config, allowedRoutes }).allowedRoutes, allowedRoutes);
  assert.throws(() => deploymentIdentity(env, { ...config, allowedRoutes: [
    { service: 'notes', method: 'GET', pathPattern: '/api/my/notes', owner: 'caller' },
  ] }));
});

test('stage 5 self-check records unauthenticated denial and deployment protections', async () => {
  const originalFetch = globalThis.fetch;
  const requested = [];
  try {
    globalThis.fetch = async (url, init) => {
      const parsed = new URL(String(url));
      requested.push({ path: parsed.pathname, attackId: init.alephEvidence?.caseId,
        requestKey: init.alephEvidence?.requestKey, init });
      if (parsed.pathname === '/api/notes') return new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
        status: 401, headers: { 'content-type': 'application/json' },
      });
      if (parsed.pathname === '/data.json') return new Response(JSON.stringify({ notes: [] }), {
        status: 200, headers: { 'content-type': 'application/json' },
      });
      if (parsed.pathname === '/aleph.json') return new Response(JSON.stringify({
        schema: 'aleph.defense.deployment.v1', step: 5, repoUrl: config.repoUrl,
        commit: 'a'.repeat(40), publicAppUrl: 'https://student-defense-123.vercel.app',
        allowedRoutes: config.allowedRoutes,
        originalApiUrl: config.originalApiUrl,
      }), { status: 200, headers: { 'content-type': 'application/json' } });
      if (parsed.pathname === '/api/auth') return new Response(JSON.stringify({ error: 'NOT_FOUND' }), {
        status: 404, headers: { 'content-type': 'application/json' },
      });
      return new Response('ok', { status: 200, headers: { 'X-Content-Type-Options': 'nosniff' } });
    };
    const results = await runAttackChecks(config);
    assert.equal(results.length, 6);
    assert.match(results[0].observed, /HTTP 401/u);
    assert.match(results[2].observed, /HTTP 200; bodyBytes=\d+; jsonArrayLength=null; jsonReady=null; method=GET; urlSha256=[a-f0-9]{64}/u);
    assert.match(results[4].observed, /HTTP 200; bodyBytes=\d+; jsonArrayLength=null; jsonReady=null; method=GET; urlSha256=[a-f0-9]{64}/u);
    assert.match(results[5].observed, /HTTP 404; bodyBytes=\d+; jsonArrayLength=null; jsonReady=null; method=GET; urlSha256=[a-f0-9]{64}/u);
    assert.deepEqual(requested.map(item => item.path), ['/api/notes', '/data.json', '/aleph.json', '/', '/', '/api/auth']);
    assert.deepEqual(requested.map(item => item.attackId), results.map(item => item.attackId));
    assert.equal(new Set(requested.map(item => item.requestKey)).size, requested.length);
    assert.ok(requested.every(item => typeof item.requestKey === 'string' && item.requestKey.length >= 16));
    assert.ok(results.every(item => /^HTTP \d{3}; bodyBytes=\d+; jsonArrayLength=(?:\d+|null); jsonReady=(?:true|false|null); method=GET; urlSha256=[a-f0-9]{64}$/u.test(item.observed)));
    assert.equal(requested[0].init.redirect, 'error');
    assert.equal(requested[0].init.headers?.Authorization, undefined);
  } finally {
    globalThis.fetch = originalFetch;
  }
});

test('stage 12 correlates each request through alephEvidence and leaves unrequested live checks not_run', async () => {
  const originalFetch = globalThis.fetch;
  const originalTextEncoder = globalThis.TextEncoder;
  const requested = [];
  const stage12 = { ...config, step: 12, originalApiUrl: config.originalApiUrl };
  const textOnly = response => Object.assign(response, {
    arrayBuffer: async () => { throw new TypeError('arrayBuffer unavailable in isolated runner'); },
  });
  try {
    globalThis.TextEncoder = undefined;
    globalThis.fetch = async (url, init) => {
      const parsed = new URL(String(url));
      const attackId = init.alephEvidence?.caseId;
      assert.equal(typeof init.alephEvidence?.requestKey, 'string');
      assert.ok(init.alephEvidence.requestKey.length >= 16);
      assert.equal(parsed.searchParams.has('attackId'), false);
      requested.push({ path: parsed.pathname, attackId, requestKey: init.alephEvidence.requestKey });
      const headers = { 'x-vercel-id': `trace-${attackId}` };
      if (parsed.pathname === '/api/notes' || parsed.pathname === '/api/notices') {
        return textOnly(new Response(JSON.stringify({ error: 'UNAUTHORIZED' }), {
          status: 401, headers: { ...headers, 'content-type': 'application/json' },
        }));
      }
      if (parsed.pathname === '/data.json') return textOnly(new Response(JSON.stringify({ notes: [] }), { status: 200, headers }));
      if (parsed.pathname === '/aleph.json') return textOnly(new Response(JSON.stringify({
        schema: 'aleph.defense.deployment.v1', step: 12, repoUrl: stage12.repoUrl,
        commit: 'a'.repeat(40), publicAppUrl: 'https://student-defense-123.vercel.app',
        originalApiUrl: stage12.originalApiUrl, allowedRoutes: stage12.allowedRoutes,
      }), { status: 200, headers }));
      if (parsed.pathname === '/api/auth') return textOnly(new Response(JSON.stringify({ error: 'NOT_FOUND' }), {
        status: 404, headers: { ...headers, 'content-type': 'application/json' },
      }));
      if (parsed.pathname === '/api/operations') return textOnly(new Response(JSON.stringify({
        error: 'UNAUTHORIZED', requestId: 'server-request-id', checkedAt: new Date().toISOString(),
      }), { status: 401, headers: { ...headers, 'content-type': 'application/json' } }));
      return textOnly(new Response('ok', { status: 200, headers: { ...headers, 'x-content-type-options': 'nosniff' } }));
    };
    const results = await runAttackChecks(stage12);
    const requestIds = [
      'anonymous_notes_api', 'public_json_empty', 'deployment_identity', 'security_header',
      'browser_supabase_key_absent', 'auth_proxy_restricts_routes', 'anonymous_notices_api',
      'operations_requires_auth', 'step_up_live_block', 'verified_backup_restore', 'device_approval_live',
    ];
    assert.deepEqual(results.map(result => result.attackId), requestIds);
    assert.deepEqual(requested.map(item => item.attackId), requestIds.filter(id =>
      !['step_up_live_block', 'verified_backup_restore', 'device_approval_live'].includes(id)));
    assert.ok(results.filter(result => requested.some(item => item.attackId === result.attackId))
      .every(result => result.result !== 'not_run'));
    assert.equal(new Set(requested.map(item => item.requestKey)).size, requested.length);
    const evidence = getLastCheckEvidence();
    assert.deepEqual(evidence.map(item => item.attackId), requestIds);
    assert.deepEqual(evidence.filter(item => item.requestId).map(item => item.requestId),
      requested.map(item => item.requestKey));
    assert.ok(evidence.filter(item => item.requestId).every(item => typeof item.checkedAt === 'string'));
    assert.ok(evidence.filter(item => !item.requestId).every(item => item.checkedAt === null));
    assert.ok(results.filter(result => requested.some(item => item.attackId === result.attackId))
      .every(result => /^HTTP \d{3}; bodyBytes=\d+; jsonArrayLength=(?:\d+|null); jsonReady=(?:true|false|null); method=GET; urlSha256=[a-f0-9]{64}$/u.test(result.observed)
        && result.observed.length <= 300));
    assert.ok(results.filter(result => !requested.some(item => item.attackId === result.attackId))
      .every(result => result.observed === 'not_run'));
  } finally {
    globalThis.fetch = originalFetch;
    globalThis.TextEncoder = originalTextEncoder;
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

test('auth proxy rejects oversized credential bodies before contacting Supabase', async () => {
  let calls = 0;
  const proxy = createAuthProxy({ config: authProxyConfig, env: authProxyEnv,
    fetchImpl: async () => { calls += 1; return new Response(null, { status: 204 }); } });
  const response = responseStub();
  await proxy({ method: 'POST', query: { path: 'token', grant_type: 'password' }, headers: {},
    body: { email: 'a@example.test', password: 'p'.repeat(1025) },
  }, response);
  assert.equal(response.statusCode, 400);
  assert.equal(calls, 0);
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

test('Vercel auth route rejects oversized request bodies with a JSON error', async () => {
  const response = responseStub();
  await authHandler({ method: 'POST', body: 'x'.repeat(16 * 1024 + 1) }, response);
  assert.equal(response.statusCode, 413);
  assert.deepEqual(response.payload, { error: 'REQUEST_TOO_LARGE' });
});
