import assert from 'node:assert/strict';
import test from 'node:test';
import { handleStage12ChecksRequest } from '../src/stage12-checks.mjs';

function response() {
  return { headers: {}, statusCode: 0, body: null,
    setHeader(key, value) { this.headers[key.toLowerCase()] = value; },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; } };
}

test('stage 12 public checks expose live results with unique evidence keys and honest not_run rows', async () => {
  const originalFetch = globalThis.fetch;
  const requests = [];
  try {
    globalThis.fetch = async (url, init) => {
      const parsed = new URL(String(url));
      requests.push({ path: parsed.pathname, evidence: init.alephEvidence, method: init.method,
        query: parsed.search });
      const json = (value, status) => new Response(JSON.stringify(value), {
        status, headers: { 'content-type': 'application/json', 'x-content-type-options': 'nosniff' },
      });
      if (parsed.pathname === '/api/notes' || parsed.pathname === '/api/notices'
          || parsed.pathname === '/api/operations') return json({ error: 'UNAUTHORIZED' }, 401);
      if (parsed.pathname === '/data.json') return json({ notes: [] }, 200);
      if (parsed.pathname === '/aleph.json') return json({ step: 12, allowedRoutes: [{ method: 'GET' }] }, 200);
      if (parsed.pathname === '/api/auth') return json({ error: 'NOT_FOUND' }, 404);
      return new Response('<!doctype html><title>ok</title>', { status: 200,
        headers: { 'content-type': 'text/html', 'x-content-type-options': 'nosniff' } });
    };

    const result = response();
    await handleStage12ChecksRequest({ method: 'GET', query: {} }, result,
      { VERCEL_GIT_COMMIT_SHA: 'c'.repeat(40) });

    assert.equal(result.statusCode, 200);
    assert.equal(result.headers['cache-control'], 'no-store');
    assert.equal(result.body.total, 11);
    assert.equal(result.body.blocked, 8);
    assert.equal(result.body.failed, 0);
    assert.equal(result.body.executed, 8);
    assert.equal(result.body.notRun, 3);
    assert.equal(result.body.commit, 'c'.repeat(40));
    assert.equal(requests.length, 8);
    assert.equal(new Set(requests.map(item => item.evidence.requestKey)).size, requests.length);
    assert.ok(requests.every(item => item.evidence.caseId && item.method === 'GET' && item.query !== '?attackId=1'));
    assert.ok(result.body.attempts.filter(item => item.observed !== 'not_run')
      .every(item => item.requestId && item.checkedAt && /^HTTP \d{3}; bodyBytes=\d+; jsonArrayLength=(?:\d+|null); jsonReady=(?:true|false|null); method=GET(?:; urlSha256=[a-f0-9]{64})?$/u.test(item.observed)));
    assert.ok(result.body.attempts.filter(item => item.observed === 'not_run')
      .every(item => item.result === 'not_run' && item.requestId === null && item.checkedAt === null));
  } finally {
    globalThis.fetch = originalFetch;
  }
});
