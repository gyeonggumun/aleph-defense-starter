import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { planPolicyRestore } from '../scripts/recover-policy.mjs';
import { handleRestoreNote } from '../src/restore-note.mjs';

const hash = value => createHash('sha256').update(value).digest('hex');
const id = '11111111-1111-4111-8111-111111111111';
const owner = '22222222-2222-4222-8222-222222222222';
const otherId = '33333333-3333-4333-8333-333333333333';

function response() {
  return { headers: {}, setHeader(key, value) { this.headers[key] = value; },
    status(code) { this.code = code; return this; }, json(value) { this.body = value; return this; } };
}

function database(rows) {
  return { from(table) {
    assert.equal(table, 'vault_notes');
    const query = { operation: 'read', filters: [],
      select() { return this; }, eq(key, value) { this.filters.push([key, value]); return this; },
      update(value) { this.operation = 'update'; this.value = value; return this; },
      insert(value) { this.operation = 'insert'; this.value = value; return this; },
      async maybeSingle() {
        const row = rows.find(item => this.filters.every(([key, value]) => item[key] === value));
        if (this.operation === 'read') return { data: row ?? null, error: null };
        if (this.operation === 'update' && row) Object.assign(row, this.value);
        if (this.operation === 'insert' && !rows.some(item => item.id === this.value.id)) {
          rows.push({ ...this.value });
          return { data: rows.at(-1), error: null };
        }
        return { data: this.operation === 'update' ? row ?? null : null, error: null };
      },
    };
    return query;
  } };
}

test('verified policy copy changes only trial notes and preserves audit/other services', () => {
  const backup = JSON.stringify({ schema: 'aleph.test-policy.v1', services: { notes: { allow: 'owner' } } });
  const trial = JSON.stringify({ schema: 'aleph.test-policy.v1',
    services: { notes: { allow: 'all' }, billing: { allow: 'staff' } }, audit: ['kept'] });
  assert.throws(() => planPolicyRestore(backup, trial, hash('wrong')), /BACKUP_NOT_VERIFIED/u);
  const { preview, next } = planPolicyRestore(backup, trial, hash(backup));
  assert.equal(preview.changed, true);
  assert.deepEqual(JSON.parse(next), { schema: 'aleph.test-policy.v1',
    services: { notes: { allow: 'owner' }, billing: { allow: 'staff' } }, audit: ['kept'] });
});

test('policy CLI previews before applying and requires confirmation', () => {
  const directory = mkdtempSync(join(tmpdir(), 'aleph-policy-'));
  try {
    const backupPath = join(directory, 'private-backup.json');
    const trialPath = join(directory, 'current.trial.json');
    const backup = JSON.stringify({ schema: 'aleph.test-policy.v1',
      services: { notes: { allow: 'owner' } } });
    const trial = JSON.stringify({ schema: 'aleph.test-policy.v1',
      services: { notes: { allow: 'all' }, other: { allow: 'kept' } }, audit: ['kept'] });
    writeFileSync(backupPath, backup);
    writeFileSync(trialPath, trial);
    const script = fileURLToPath(new URL('../scripts/recover-policy.mjs', import.meta.url));
    execFileSync(process.execPath, [script, 'preview', backupPath, trialPath, hash(backup)]);
    assert.equal(readFileSync(trialPath, 'utf8'), trial);
    assert.throws(() => execFileSync(process.execPath,
      [script, 'apply', backupPath, trialPath, hash(backup)]));
    execFileSync(process.execPath,
      [script, 'apply', backupPath, trialPath, hash(backup), hash(backup)]);
    assert.deepEqual(JSON.parse(readFileSync(trialPath, 'utf8')),
      { schema: 'aleph.test-policy.v1',
        services: { notes: { allow: 'owner' }, other: { allow: 'kept' } }, audit: ['kept'] });
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('one-note restore requires pinned backup, B identity and matching preview hashes', async () => {
  const backup = { id, owner_id: owner, title: '복구 메모', content: '검증된 가상 내용',
    content_sha256: hash('검증된 가상 내용') };
  const raw = JSON.stringify(backup);
  const settings = { RESTORE_B_USER_ID: owner, RESTORE_NOTE_BACKUP_JSON: raw,
    RESTORE_NOTE_BACKUP_SHA256: hash(raw) };
  const rows = [{ id, owner_id: owner, title: '바뀐 메모', content: '바뀐 내용' },
    { id: otherId, owner_id: otherId, title: '보존', content: '보존 내용' }];
  const services = { database: database(rows), verifyLogin: async () => ({ userId: owner }),
    deviceApproved: async () => true };
  const request = { method: 'POST', headers: { authorization: 'test' }, body: { id, confirm: false } };
  const missing = response();
  await handleRestoreNote(request, missing, { services, settings: {} });
  assert.equal(missing.code, 503);
  const anonymous = response();
  await handleRestoreNote(request, anonymous, { services: { ...services,
    verifyLogin: async () => null }, settings });
  assert.equal(anonymous.code, 401);
  const preview = response();
  await handleRestoreNote(request, preview, { services, settings });
  assert.equal(preview.code, 200);
  assert.equal(preview.body.applied, false);
  assert.equal(rows[0].content, '바뀐 내용');
  const forbidden = response();
  await handleRestoreNote(request, forbidden, { services: { ...services,
    verifyLogin: async () => ({ userId: otherId }) }, settings });
  assert.equal(forbidden.code, 403);
  const stale = response();
  await handleRestoreNote({ ...request, body: { id, confirm: true,
    expectedCurrentSha256: hash('이전 내용'),
    expectedContentSha256: preview.body.backupContentSha256 } }, stale, { services, settings });
  assert.equal(stale.code, 409);
  const applied = response();
  await handleRestoreNote({ ...request, body: { id, confirm: true,
    expectedCurrentSha256: preview.body.currentContentSha256,
    expectedContentSha256: preview.body.backupContentSha256 } }, applied, { services, settings });
  assert.equal(applied.code, 200);
  assert.equal(applied.body.restored, true);
  assert.equal(rows[0].content, backup.content);
  assert.equal(rows[0].owner_id, owner);
  assert.equal(rows[1].content, '보존 내용');
});
