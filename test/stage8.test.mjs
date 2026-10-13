import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { decide } from '../src/decider.mjs';
import { resourceZone } from '../src/resource-zone.mjs';
import { handleNoticesRequest } from '../src/notices-api.mjs';

const id = '23e19e6c-6223-4d86-a635-8c28a5e1e786';
const request = (method, path, route) => ({ requestId: randomUUID(), subjectId: 'verified-subject',
  service: 'notes', deviceRegistered: true, method, path, route,
  signals: { source: 'none' }, recentEvents: [], stepUp: { verified: false, authAgeSeconds: null } });

test('정확한 자원 ID와 경로만 사용하고 공지 수정은 검증 계약 전까지 거부', async () => {
  const own = request('PUT', `/notes/${id}`, 'PUT /notes/:id');
  const notice = request('PUT', `/notices/${id}`, 'PUT /notices/:id');
  assert.equal(resourceZone(own).id, `note:${id}`);
  assert.equal(resourceZone(notice).id, `notice:${id}`);
  assert.equal((await decide(own)).decision, 'allow');
  assert.equal((await decide(notice)).decision, 'deny');
  assert.equal((await decide(request('GET', '/notices', 'GET /notices'))).decision, 'allow');
  for (const bad of ['/notes/export', '/notes/export/now', `/notes/${id}/export`, `/notes/${id}?export=1`]) {
    assert.equal((await decide(request('GET', bad, 'GET /notes/:id'))).decision, 'deny');
  }
  assert.equal((await decide({ ...own, deviceRegistered: false })).reasonCode, 'device_not_registered');
});

function response() {
  return { headers: {}, setHeader(key, value) { this.headers[key] = value; },
    status(code) { this.code = code; return this; }, json(body) { this.body = body; return this; } };
}

function context(role, identity = { userId: 'verified-user' }) {
  let updated = false;
  const row = { id, title: '수정된 공지', content: '가상 내용' };
  const query = { update() { updated = true; return this; }, eq() { return this; },
    select() { return this; }, async maybeSingle() { return { data: row, error: null }; } };
  return { verifyLogin: async () => identity,
    database: { auth: { admin: { getUserById: async () => ({ data: { user: {
      id: 'verified-user', app_metadata: role === 'metadata-only' ? {} : { role },
      user_metadata: { role: 'instructor' },
    } }, error: null }) } }, from: () => query },
    wasUpdated: () => updated };
}

test('공지 수정은 서버가 확인한 강사 역할만 허용', async () => {
  const input = { method: 'PUT', query: { id }, headers: { authorization: 'Bearer fake' },
    body: { title: '수정된 공지', body: '가상 내용', role: 'instructor' } };
  const student = context('metadata-only');
  const denied = response();
  await handleNoticesRequest(input, denied, student);
  assert.equal(denied.code, 403);
  assert.equal(student.wasUpdated(), false);

  const instructor = context('instructor');
  const allowed = response();
  await handleNoticesRequest({ ...input, body: { ...input.body, role: 'student' } }, allowed, instructor);
  assert.equal(allowed.code, 200);
  assert.equal(instructor.wasUpdated(), true);

  const anonymous = response();
  await handleNoticesRequest(input, anonymous, context('instructor', null));
  assert.equal(anonymous.code, 401);
});
