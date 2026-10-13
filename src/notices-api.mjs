import { deviceApproved } from './device-approval.mjs';

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

function respond(response, status, payload) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  return response.status(status).json(payload);
}

function noticeFields(row) {
  return { id: row.id, title: row.title, body: row.content };
}

export async function handleNoticesRequest(request, response, suppliedContext) {
  if (!['GET', 'PUT'].includes(request.method)) {
    response.setHeader('Allow', 'GET, PUT');
    return respond(response, 405, { error: 'METHOD_NOT_ALLOWED' });
  }
  let context;
  try { context = suppliedContext ?? (await import('./notes-api.mjs')).getServices(); } catch {
    return respond(response, 503, { error: 'AUTH_OR_DATABASE_NOT_CONFIGURED' });
  }
  let identity;
  try { identity = await context.verifyLogin(request.headers?.authorization); } catch {}
  if (!identity) return respond(response, 401, { error: 'UNAUTHORIZED' });
  if (!await (context.deviceApproved ?? deviceApproved)(context.database, identity, request.headers?.['x-device-grant'])) {
    return respond(response, 403, { error: 'DEVICE_NOT_APPROVED' });
  }

  const id = request.query?.id;
  if (id !== undefined && (typeof id !== 'string' || !UUID.test(id))) {
    return respond(response, 400, { error: 'INVALID_ID' });
  }
  if (request.method === 'PUT' && !id) return respond(response, 400, { error: 'INVALID_ID' });

  try {
    if (request.method === 'GET' && !id) {
      const { data, error } = await context.database.from('instructor_notices')
        .select('id,title,content').order('created_at', { ascending: true });
      return error ? respond(response, 502, { error: 'DATA_SOURCE_UNAVAILABLE' })
        : respond(response, 200, (data ?? []).map(noticeFields));
    }
    if (request.method === 'GET') {
      const { data, error } = await context.database.from('instructor_notices')
        .select('id,title,content').eq('id', id).maybeSingle();
      if (error) return respond(response, 502, { error: 'DATA_SOURCE_UNAVAILABLE' });
      return data ? respond(response, 200, noticeFields(data))
        : respond(response, 404, { error: 'NOT_FOUND' });
    }

    // The Auth Admin response is server-controlled; request body and user_metadata are not roles.
    const { data: account, error: accountError } = await context.database.auth.admin.getUserById(identity.userId);
    if (accountError || account?.user?.id !== identity.userId
        || account.user.app_metadata?.role !== 'instructor') {
      return respond(response, 403, { error: 'FORBIDDEN' });
    }
    let body = request.body;
    if (Buffer.isBuffer(body)) body = body.toString('utf8');
    if (typeof body === 'string') {
      try { body = JSON.parse(body); } catch { return respond(response, 400, { error: 'INVALID_NOTICE' }); }
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)
        || typeof body.title !== 'string' || !body.title.trim() || body.title.length > 200
        || typeof body.body !== 'string' || !body.body.trim() || body.body.length > 5000) {
      return respond(response, 400, { error: 'INVALID_NOTICE' });
    }
    const { data, error } = await context.database.from('instructor_notices')
      .update({ title: body.title.trim(), content: body.body.trim() })
      .eq('id', id).select('id,title,content').maybeSingle();
    if (error) return respond(response, 502, { error: 'DATA_SOURCE_UNAVAILABLE' });
    return data ? respond(response, 200, noticeFields(data))
      : respond(response, 404, { error: 'NOT_FOUND' });
  } catch {
    return respond(response, 502, { error: 'DATA_SOURCE_UNAVAILABLE' });
  }
}
