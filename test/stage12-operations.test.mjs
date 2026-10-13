import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { handleOperationsRequest } from '../src/operations-api.mjs';
import { noteBackupStatus } from '../src/restore-note.mjs';

function response() {
  return { headers: {}, statusCode: 200, body: null,
    setHeader(key, value) { this.headers[key] = value; },
    status(value) { this.statusCode = value; return this; },
    json(value) { this.body = value; return this; } };
}

function context({ identity = { userId: 'verified-user' }, approved = true } = {}) {
  let databaseCalls = 0;
  const database = { from(table) {
    databaseCalls += 1;
    let selected = '';
    const query = {
      select(columns) { selected = columns; return this; },
      eq() { return this; },
      then(resolve, reject) {
        const result = table === 'vault_notes'
          ? { data: null, count: 4, error: null }
          : { data: [{ status: 'approved' }, { status: 'pending' }, { status: 'revoked' }], error: null };
        assert.equal(table === 'vault_notes' ? selected : selected, table === 'vault_notes' ? 'id' : 'status');
        return Promise.resolve(result).then(resolve, reject);
      },
    };
    return query;
  } };
  return { database, verifyLogin: async () => identity,
    deviceApproved: async () => approved, get databaseCalls() { return databaseCalls; } };
}

test('operations status requires a logged-in, server-approved device', async () => {
  const anonymousContext = context({ identity: null });
  const anonymous = response();
  await handleOperationsRequest({ method: 'GET', headers: {} }, anonymous, anonymousContext, {});
  assert.equal(anonymous.statusCode, 401);
  assert.equal(anonymous.body.error, 'UNAUTHORIZED');
  assert.equal(anonymousContext.databaseCalls, 0);

  const unapprovedContext = context({ approved: false });
  const unapproved = response();
  await handleOperationsRequest({ method: 'GET', headers: { authorization: 'Bearer fixture' } },
    unapproved, unapprovedContext, {});
  assert.equal(unapproved.statusCode, 403);
  assert.equal(unapproved.body.error, 'DEVICE_NOT_APPROVED');
  assert.equal(unapprovedContext.databaseCalls, 0);
});

test('operation response reports real code/DB summaries, labels unrun engine work, and contains no note data', async () => {
  const result = response();
  await handleOperationsRequest({ method: 'GET', headers: { authorization: 'Bearer fixture' } },
    result, context(), {});
  assert.equal(result.statusCode, 200);
  assert.match(result.headers['Cache-Control'], /no-store/u);
  assert.equal(result.body.schema, 'aleph.operations.v1');
  assert.equal(result.body.dataSummary.ownNoteCount, 4);
  assert.equal(result.body.dataSummary.noteBodiesIncluded, false);
  assert.deepEqual(result.body.revocation.deviceStatus,
    { approved: 1, pending: 1, revoked: 1, other: 0 });
  assert.equal(result.body.decider.engineRuntime, 'unverified');
  assert.equal(result.body.detection.liveEventFeed, 'not_connected');
  assert.deepEqual(result.body.assaultSuite,
    { total: 41, executedInThisReport: 0, passedInThisReport: 0, status: 'not_run' });
  assert.equal(result.body.revocation.actualRevocation, 'not_executed');
  assert.equal(result.body.restore.policySnapshot.status, 'unavailable');
  assert.deepEqual(result.body.records.slice(0, 2).map(row => row.actual), ['allow', 'deny / device_not_registered']);
  assert.equal(result.body.records[2].actual, 'propose_revocation');
  assert.ok(result.body.records.every(row => row.requestId && row.checkedAt));
  const serialized = JSON.stringify(result.body);
  assert.doesNotMatch(serialized, /title|content|owner_id|credential_id|public_key|private key/iu);
});

test('note backup status verifies pinned content but never returns the note body', () => {
  const backup = { id: '11111111-1111-4111-8111-111111111111',
    owner_id: '22222222-2222-4222-8222-222222222222', title: 'fixture', content: 'private fixture' };
  backup.content_sha256 = createHash('sha256').update(backup.content).digest('hex');
  const raw = JSON.stringify(backup);
  const settings = { RESTORE_NOTE_BACKUP_JSON: raw,
    RESTORE_NOTE_BACKUP_SHA256: createHash('sha256').update(raw).digest('hex'),
    RESTORE_B_USER_ID: backup.owner_id };
  assert.deepEqual(noteBackupStatus(settings),
    { status: 'verified', reasonCode: 'PINNED_HASH_AND_OWNER_CHECKED' });
  assert.deepEqual(noteBackupStatus({}),
    { status: 'unavailable', reasonCode: 'VERIFIED_BACKUP_UNAVAILABLE' });
  assert.equal(JSON.stringify(noteBackupStatus(settings)).includes(backup.content), false);
});

test('operation room UI is hidden before device approval and its inline module parses', () => {
  const html = readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const source = html.split('<script type="module">')[1]?.split('</script>')[0];
  assert.ok(source);
  assert.match(html, /id="operations-panel"[^>]*hidden/u);
  assert.match(source, /operationsPanel\.hidden = !signedIn \|\| !deviceReady\(\)/u);
  assert.match(source, /operationsPanel\.hidden = false/u);
  assert.doesNotMatch(source, /\.innerHTML\s*=/u);
  const executable = source.split(/\r?\n/u).filter(line => !line.trim().startsWith('import ')).join('\n');
  const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
  assert.doesNotThrow(() => new AsyncFunction(executable));
});
