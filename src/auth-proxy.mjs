const BEARER_JWT = /^Bearer ([A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)$/u;
const GRANT_TYPES = new Set(['password', 'refresh_token']);
const LOGOUT_SCOPES = new Set(['global', 'local', 'others']);
const MAX_EMAIL_BYTES = 320;
const MAX_PASSWORD_BYTES = 1024;
const MAX_REFRESH_TOKEN_BYTES = 8192;

function queryValue(request, name) {
  const value = request.query?.[name];
  return typeof value === 'string' ? value : undefined;
}

function parseBody(request) {
  let body = request.body;
  if (Buffer.isBuffer(body)) body = body.toString('utf8');
  if (typeof body === 'string') {
    try { body = JSON.parse(body); } catch { return null; }
  }
  return body && typeof body === 'object' && !Array.isArray(body) ? body : null;
}

function json(response, status, payload) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  return response.status(status).json(payload);
}

function serverCredentials(env, config) {
  const url = env.SUPABASE_URL;
  const secretKey = env.SUPABASE_SECRET_KEY;
  let projectUrl;
  let issuer;
  try {
    projectUrl = new URL(url);
    issuer = new URL(config.identityProvider?.issuer);
  } catch { return null; }
  if (typeof secretKey !== 'string' || !secretKey.trim() || secretKey !== secretKey.trim()
      || projectUrl.protocol !== 'https:' || projectUrl.pathname !== '/'
      || projectUrl.username || projectUrl.password || projectUrl.search || projectUrl.hash
      || projectUrl.origin !== issuer.origin || issuer.pathname !== '/auth/v1') return null;
  return { projectUrl, secretKey };
}

export function createAuthProxy({ config, env = process.env, fetchImpl = fetch } = {}) {
  return async function handleAuthProxy(request, response) {
    response.setHeader('Cache-Control', 'no-store');
    const route = queryValue(request, 'path');
    const method = request.method;
    let grantType;
    let scope;
    let body;
    let userAuthorization;

    if (route === 'token' && method === 'POST') {
      grantType = queryValue(request, 'grant_type');
      if (!GRANT_TYPES.has(grantType)) return json(response, 404, { error: 'NOT_FOUND' });
      const input = parseBody(request);
      if (grantType === 'password') {
        if (typeof input?.email !== 'string' || !input.email.trim()
            || Buffer.byteLength(input.email, 'utf8') > MAX_EMAIL_BYTES
            || typeof input.password !== 'string' || !input.password
            || Buffer.byteLength(input.password, 'utf8') > MAX_PASSWORD_BYTES) {
          return json(response, 400, { error: 'INVALID_CREDENTIALS' });
        }
        body = { email: input.email, password: input.password };
      } else {
        if (typeof input?.refresh_token !== 'string' || !input.refresh_token.trim()) {
          return json(response, 400, { error: 'INVALID_SESSION' });
        }
        if (Buffer.byteLength(input.refresh_token, 'utf8') > MAX_REFRESH_TOKEN_BYTES) {
          return json(response, 400, { error: 'INVALID_SESSION' });
        }
        body = { refresh_token: input.refresh_token };
      }
    } else if (route === 'logout' && method === 'POST') {
      scope = queryValue(request, 'scope') ?? 'global';
      if (!LOGOUT_SCOPES.has(scope)) return json(response, 400, { error: 'INVALID_SCOPE' });
      const match = BEARER_JWT.exec(request.headers?.authorization ?? '');
      if (!match) return json(response, 401, { error: 'UNAUTHORIZED' });
      userAuthorization = `Bearer ${match[1]}`;
    } else {
      if (route === 'token' || route === 'logout') {
        response.setHeader('Allow', 'POST');
        return json(response, 405, { error: 'METHOD_NOT_ALLOWED' });
      }
      return json(response, 404, { error: 'NOT_FOUND' });
    }

    const credentials = serverCredentials(env, config);
    if (!credentials) return json(response, 503, { error: 'AUTH_SERVICE_NOT_CONFIGURED' });

    const upstreamUrl = new URL(`/auth/v1/${route}`, credentials.projectUrl);
    if (grantType) upstreamUrl.searchParams.set('grant_type', grantType);
    if (scope) upstreamUrl.searchParams.set('scope', scope);
    const headers = new Headers({ apikey: credentials.secretKey, accept: 'application/json' });
    if (userAuthorization) headers.set('authorization', userAuthorization);
    if (body) headers.set('content-type', 'application/json');

    try {
      const upstream = await fetchImpl(upstreamUrl, {
        method: 'POST', headers, body: body ? JSON.stringify(body) : undefined,
        redirect: 'error', signal: AbortSignal.timeout(10000),
      });
      response.setHeader('Cache-Control', 'no-store');
      const contentType = upstream.headers.get('content-type');
      if (contentType) response.setHeader('Content-Type', contentType);
      response.status(upstream.status);
      return response.send(Buffer.from(await upstream.arrayBuffer()));
    } catch {
      return json(response, 502, { error: 'AUTH_SERVICE_UNAVAILABLE' });
    }
  };
}
