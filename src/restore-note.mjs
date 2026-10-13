import { createHash, timingSafeEqual } from 'node:crypto';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const SHA256 = /^[a-f0-9]{64}$/iu;
const hash = value => createHash('sha256').update(value).digest('hex');
const equalHash = (a, b) => SHA256.test(a ?? '') && SHA256.test(b ?? '')
  && timingSafeEqual(Buffer.from(a.toLowerCase(), 'hex'), Buffer.from(b.toLowerCase(), 'hex'));

function reply(response, status, body) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  return response.status(status).json(body);
}

function bodyOf(request) {
  let body = request.body;
  if (Buffer.isBuffer(body)) body = body.toString('utf8');
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return null; }
  }
  return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
}

function checkedBackup(raw, pinnedHash, bUserId) {
  if (typeof raw !== 'string' || !equalHash(hash(raw), pinnedHash)) return null;
  let note;
  try { note = JSON.parse(raw); } catch { return null; }
  if (!UUID.test(note?.id ?? '') || !UUID.test(note?.owner_id ?? '')
      || note.owner_id !== bUserId || typeof note.title !== 'string'
      || !note.title.trim() || note.title.length > 200
      || typeof note.content !== 'string' || !note.content.trim()
      || note.content.length > 5000 || !equalHash(hash(note.content), note.content_sha256)) return null;
  return note;
}

// The backup must have been captured and its digest pinned before the incident.
// An absent or altered backup cannot authorize a write.
export async function handleRestoreNote(request, response, options = {}) {
  if (request.method !== 'POST') {
    response.setHeader('Allow', 'POST');
    return reply(response, 405, { error: 'METHOD_NOT_ALLOWED' });
  }
  const settings = options.settings ?? process.env;
  const bUserId = settings.RESTORE_B_USER_ID;
  let services;
  try {
    services = options.services ?? (await import('./notes-api.mjs')).getServices();
  } catch {
    return reply(response, 503, { error: 'AUTH_OR_DATABASE_NOT_CONFIGURED' });
  }
  let identity;
  try { identity = await services.verifyLogin(request.headers?.authorization); } catch {}
  if (!identity) return reply(response, 401, { error: 'UNAUTHORIZED' });
  const backup = checkedBackup(settings.RESTORE_NOTE_BACKUP_JSON,
    settings.RESTORE_NOTE_BACKUP_SHA256, bUserId);
  if (!backup) return reply(response, 503, { error: 'VERIFIED_BACKUP_UNAVAILABLE' });
  if (identity.userId !== bUserId) return reply(response, 403, { error: 'RESTORE_FORBIDDEN' });
  const body = bodyOf(request);
  if (!body || body.id !== backup.id || typeof body.confirm !== 'boolean') {
    return reply(response, 400, { error: 'INVALID_RESTORE_REQUEST' });
  }

  try {
    const { data: current, error: readError } = await services.database.from('vault_notes')
      .select('id,owner_id,title,content').eq('id', backup.id).maybeSingle();
    if (readError) return reply(response, 502, { error: 'DATA_SOURCE_UNAVAILABLE' });
    if (current && current.owner_id !== bUserId) {
      return reply(response, 409, { error: 'OWNER_MISMATCH' });
    }
    const preview = { id: backup.id, owner_id: bUserId,
      currentContentSha256: current ? hash(current.content) : null,
      backupContentSha256: backup.content_sha256,
      titleWillChange: current?.title !== backup.title };
    if (!body.confirm) return reply(response, 200, { ...preview, applied: false });
    if (!equalHash(body.expectedContentSha256, backup.content_sha256)) {
      return reply(response, 409, { error: 'BACKUP_HASH_MISMATCH' });
    }
    if (body.expectedCurrentSha256 !== preview.currentContentSha256) {
      return reply(response, 409, { error: 'CURRENT_NOTE_CHANGED' });
    }
    const query = current
      ? services.database.from('vault_notes').update({ title: backup.title, content: backup.content })
        .eq('id', backup.id).eq('owner_id', bUserId)
        .eq('content', current.content).eq('title', current.title)
      : services.database.from('vault_notes').insert({ id: backup.id, owner_id: bUserId,
        title: backup.title, content: backup.content });
    const { data: saved, error: writeError } = await query
      .select('id,owner_id,title,content').maybeSingle();
    if (writeError || !saved) return reply(response, 409, { error: 'RESTORE_NOT_APPLIED' });
    if (saved.id !== backup.id || saved.owner_id !== bUserId || saved.title !== backup.title
        || !equalHash(hash(saved.content), backup.content_sha256)) {
      return reply(response, 502, { error: 'RESTORE_VERIFICATION_FAILED' });
    }
    return reply(response, 200, { id: saved.id, owner_id: saved.owner_id,
      content_sha256: backup.content_sha256, restored: true });
  } catch {
    return reply(response, 502, { error: 'DATA_SOURCE_UNAVAILABLE' });
  }
}
