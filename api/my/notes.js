import { handleNotesRequest } from '../../src/notes-api.mjs';

function respond(response, status, payload) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  return response.status(status).json(payload);
}

export default function handler(request, response) {
  const queryKeys = Object.keys(request.query ?? {});
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return respond(response, 405, { error: 'METHOD_NOT_ALLOWED' });
  }
  if (queryKeys.length) return respond(response, 400, { error: 'QUERY_NOT_ALLOWED' });
  return handleNotesRequest(request, response);
}
