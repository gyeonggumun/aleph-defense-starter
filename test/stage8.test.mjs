import assert from 'node:assert/strict';
import test from 'node:test';
import { randomUUID } from 'node:crypto';
import { decide } from '../src/decider.mjs';
import { resourceZone } from '../src/resource-zone.mjs';
import { handleNoticesRequest } from '../src/notices-api.mjs';

const id = '23e19e6c-6223-4d86-a635-8c28a5e1e786';
const request = (method, path, route) => ({ schema: 'aleph.decision.v1', requestId: randomUUID(),
  classId: 'class_fixture', projectId: 'project_fixture', subjectId: 'learner_fixture',
  deviceId: 'aaaaaaaaaaaaaaaa', service: 'notes', deviceRegistered: true,
  method, path, route, queryLength: 0,
  signals: { source: 'none' }, recentEvents: [], stepUp: { verified: false, authAgeSeconds: null } });

test('정확한 자기 목록·메모 읽기만 허용하고 모호한 목록과 쓰기는 거부', async () => {
  const ownList = request('GET', '/api/my/notes', 'GET /api/my/notes');
  const ownItem = request('GET', `/api/notes/${id}`, 'GET /api/notes/:id');
  const aliasItem = request('GET', `/notes/${id}`, 'GET /notes/:id');
  assert.equal(resourceZone(ownList).id, 'notes:collection');
  assert.equal(resourceZone(ownItem).id, `note:${id}`);
  assert.equal((await decide(ownList)).decision, 'allow');
  assert.equal((await decide(ownItem)).decision, 'allow');
  assert.equal((await decide(aliasItem)).decision, 'allow');

  for (const requestToDeny of [
    request('GET', '/api/notes', 'GET /api/notes'),
    request('GET', '/notes', 'GET /notes'),
    request('PUT', `/api/notes/${id}`, 'PUT /api/notes/:id'),
    request('DELETE', `/api/notes/${id}`, 'DELETE /api/notes/:id'),
    request('PUT', `/api/notices/${id}`, 'PUT /api/notices/:id'),
    request('GET', '/api/notes/export', 'GET /api/notes/:id'),
    request('GET', `/api/notes/${id}`, 'GET /notes/:id'),
    { ...ownList, queryLength: 8 },
  ]) assert.equal((await decide(requestToDeny)).decision, 'deny');

  assert.equal((await decide(request('GET', '/api/notices', 'GET /api/notices'))).decision, 'allow');
  assert.equal((await decide({ ...ownList, deviceRegistered: false })).reasonCode, 'device_not_registered');
  assert.equal((await decide({ ...ownList, signals: { source: 'judge_fixture', region: 'foreign',
    network: 'unusual', hour: 3 }, recentEvents: [{ kind: 'risk_signal', ageSeconds: 60, count: 20 }] })).decision, 'step_up');
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
  return { verifyLogin: async () => identity, deviceApproved: async () => true,
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
