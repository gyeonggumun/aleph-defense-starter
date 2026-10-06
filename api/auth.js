import config from '../aleph.config.json' with { type: 'json' };
import { createAuthProxy } from '../src/auth-proxy.mjs';

const handleAuthProxy = createAuthProxy({ config });

export default function handler(request, response) {
  return handleAuthProxy(request, response);
}
