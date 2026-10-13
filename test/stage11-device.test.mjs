import assert from 'node:assert/strict';
import { hkdfSync } from 'node:crypto';
import { test } from 'node:test';
import { SignJWT } from 'jose';
import config from '../aleph.config.json' with { type: 'json' };
import { deviceApproved } from '../src/device-approval.mjs';
import { handleNotesRequest } from '../src/notes-api.mjs';

const userId = '11111111-1111-4111-8111-111111111111';
const credentialId = 'registered_device_1';
const identity = { kind: 'student', userId };
process.env.SUPABASE_SECRET_KEY = 'unit-test-only-secret';

function database(status) {
  const filters = {};
  const query = {
    select() { return this; },
    eq(key, value) { filters[key] = value; return this; },
    async maybeSingle() {
      return { data: status === 'approved' && filters.owner_id === userId
        && filters.credential_id === credentialId && filters.status === 'approved'
        ? { credential_id: credentialId } : null, error: null };
    },
  };
  return { from(name) { assert.equal(name, 'device_credentials'); return query; } };
}

function response() {
  return {
    headers: {}, statusCode: 200, body: null,
    setHeader(key, value) { this.headers[key] = value; },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; },
  };
}

async function grant() {
  const key = new Uint8Array(hkdfSync('sha256', process.env.SUPABASE_SECRET_KEY,
    'aleph-device-approval', 'device-grant-v1', 32));
  return new SignJWT({ cid: credentialId }).setProtectedHeader({ alg: 'HS256' })
    .setSubject(userId).setIssuer(new URL(config.publicAppUrl).origin)
    .setAudience('aleph-protected-data').setIssuedAt().setExpirationTime('5m').sign(key);
}

test('logged-in request without approved device proof gets JSON 403 and no data query', async () => {
  const result = response();
  await handleNotesRequest({ method: 'GET', headers: { authorization: 'Bearer dummy' }, query: {} },
    result, { verifyLogin: async () => identity, database: database('pending') });
  assert.equal(result.statusCode, 403);
  assert.equal(result.body.error, 'DEVICE_NOT_APPROVED');
  assert.match(result.headers['Content-Type'], /json/u);
});

test('a signed grant still needs an approved server record for the same user and credential', async () => {
  const proof = await grant();
  assert.equal(await deviceApproved(database('pending'), identity, proof), false);
  assert.equal(await deviceApproved(database('approved'), identity, proof), true);
  assert.equal(await deviceApproved(database('approved'),
    { ...identity, userId: '22222222-2222-4222-8222-222222222222' }, proof), false);
  assert.equal(await deviceApproved(database('approved'), identity, `${proof}x`), false);
});
