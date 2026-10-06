import { randomUUID } from 'node:crypto';
import { createClient } from '@supabase/supabase-js';
import config from '../aleph.config.json' with { type: 'json' };
import { createLoginVerifier } from './verify-login.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
let services;

function getServices() {
  if (services) return services;
  const url = process.env.SUPABASE_URL;
  const secretKey = process.env.SUPABASE_SECRET_KEY;
  if (!url || !secretKey) throw new Error('missing_server_configuration');

  const projectUrl = new URL(url);
  const authUrl = new URL(config.identityProvider?.issuer);
  if (projectUrl.protocol !== 'https:' || projectUrl.pathname !== '/'
      || projectUrl.search || projectUrl.hash || projectUrl.origin !== authUrl.origin) {
    throw new Error('invalid_server_configuration');
  }

  const database = createClient(url, secretKey, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false },
  });
  services = {
    database,
    verifyLogin: createLoginVerifier({ config, supabaseSecretKey: secretKey }),
  };
  return services;
}

function respond(response, status, payload) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  return response.status(status).json(payload);
}

function parseBody(request) {
  let value = request.body;
  if (Buffer.isBuffer(value)) value = value.toString('utf8');
  if (typeof value === 'string') {
    try { value = JSON.parse(value); } catch { return null; }
  }
  return value && typeof value === 'object' && !Array.isArray(value) ? value : null;
}

function noteFields(row) {
  return { id: row.id, title: row.title, body: row.content };
}

function validateNote(body) {
  if (!body || typeof body.title !== 'string' || !body.title.trim()
      || body.title.length > 200 || typeof body.body !== 'string'
      || !body.body.trim() || body.body.length > 5000) return null;
  return { title: body.title.trim(), content: body.body.trim() };
}

export async function handleNotesRequest(request, response) {
  response.setHeader('Cache-Control', 'no-store');
  const method = request.method;
  if (!['GET', 'POST', 'PUT', 'DELETE'].includes(method)) {
    response.setHeader('Allow', 'GET, POST, PUT, DELETE');
    return respond(response, 405, { error: 'METHOD_NOT_ALLOWED' });
  }

  let context;
  try { context = getServices(); } catch {
    return respond(response, 503, { error: 'AUTH_OR_DATABASE_NOT_CONFIGURED' });
  }
  let identity = null;
  try { identity = await context.verifyLogin(request.headers?.authorization); } catch {}
  if (!identity) return respond(response, 401, { error: 'UNAUTHORIZED', message: '로그인이 필요합니다.' });

  const rawId = request.query?.id;
  const id = typeof rawId === 'string' ? rawId : undefined;
  if (rawId !== undefined && (!id || !UUID.test(id))) {
    return respond(response, 400, { error: 'INVALID_ID' });
  }

  try {
    if (method === 'GET' && !id) {
      const { data, error } = await context.database
        .from('vault_notes')
        .select('id,title,content')
        .or(`owner_id.is.null,owner_id.eq.${identity.userId}`)
        .order('created_at', { ascending: true });
      if (error) return respond(response, 502, { error: 'DATA_SOURCE_UNAVAILABLE' });
      return respond(response, 200, (data ?? []).map(noteFields));
    }

    if (method === 'GET') {
      const { data, error } = await context.database.from('vault_notes')
        .select('id,title,content').eq('id', id).maybeSingle();
      if (error) return respond(response, 502, { error: 'DATA_SOURCE_UNAVAILABLE' });
      return data ? respond(response, 200, noteFields(data))
        : respond(response, 404, { error: 'NOT_FOUND' });
    }

    if (method === 'POST') {
      const body = parseBody(request);
      const fields = validateNote(body);
      const noteId = body?.id === undefined ? randomUUID() : body.id;
      if (!fields || typeof noteId !== 'string' || !UUID.test(noteId)) {
        return respond(response, 400, { error: 'INVALID_NOTE' });
      }
      const { data, error } = await context.database.from('vault_notes')
        .insert({ id: noteId, owner_id: identity.userId, ...fields }).select('id').single();
      if (error) return respond(response, error.code === '23505' ? 409 : 502,
        { error: error.code === '23505' ? 'NOTE_ID_ALREADY_EXISTS' : 'DATA_SOURCE_UNAVAILABLE' });
      return respond(response, 201, { id: data.id });
    }

    if (!id) return respond(response, 400, { error: 'INVALID_ID' });
    if (method === 'PUT') {
      const fields = validateNote(parseBody(request));
      if (!fields) return respond(response, 400, { error: 'INVALID_NOTE' });
      const { data, error } = await context.database.from('vault_notes')
        .update(fields).eq('id', id).select('id,title,content').maybeSingle();
      if (error) return respond(response, 502, { error: 'DATA_SOURCE_UNAVAILABLE' });
      return data ? respond(response, 200, noteFields(data))
        : respond(response, 404, { error: 'NOT_FOUND' });
    }

    const { data, error } = await context.database.from('vault_notes')
      .delete().eq('id', id).select('id').maybeSingle();
    if (error) return respond(response, 502, { error: 'DATA_SOURCE_UNAVAILABLE' });
    return data ? respond(response, 200, { id: data.id })
      : respond(response, 404, { error: 'NOT_FOUND' });
  } catch {
    return respond(response, 502, { error: 'DATA_SOURCE_UNAVAILABLE' });
  }
}
