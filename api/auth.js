import config from '../aleph.config.json' with { type: 'json' };
import { createAuthProxy } from '../src/auth-proxy.mjs';

const handleAuthProxy = createAuthProxy({ config });

export default function handler(request, response) {
  const body = request.body;
  const size = Buffer.isBuffer(body) ? body.length
    : Buffer.byteLength(typeof body === 'string' ? body : JSON.stringify(body ?? null) ?? '');
  if (size > 16 * 1024) {
    response.setHeader('Cache-Control', 'no-store');
    response.setHeader('Content-Type', 'application/json; charset=utf-8');
    return response.status(413).json({ error: 'REQUEST_TOO_LARGE' });
  }
  return handleAuthProxy(request, response);
}
