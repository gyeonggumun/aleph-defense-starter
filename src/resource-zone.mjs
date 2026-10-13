const ITEM = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;

// Engine-verified service, method, route, and exact path identify the zone.
// The owner and instructor role are deliberately left to the authenticated API.
export function resourceZone(request) {
  if (request?.service !== 'notes' || typeof request.path !== 'string') return null;
  if (request.path === '/notes' && request.method === 'GET'
      && request.route === 'GET /notes') {
    return { id: 'notes:collection', zone: 'own_notes' };
  }
  if (request.path === '/notices' && request.method === 'GET'
      && request.route === 'GET /notices') {
    return { id: 'notices:collection', zone: 'instructor_notice' };
  }
  const segments = request.path.split('/');
  if (segments.length !== 3 || segments[0] !== '' || !ITEM.test(segments[2])) return null;
  const id = segments[2];
  if (segments[1] === 'notes' && ['GET', 'PUT'].includes(request.method)
      && request.route === `${request.method} /notes/:id`) {
    return { id: `note:${id}`, zone: 'own_note' };
  }
  if (segments[1] === 'notices' && ['GET', 'PUT'].includes(request.method)
      && request.route === `${request.method} /notices/:id`) {
    return { id: `notice:${id}`, zone: 'instructor_notice' };
  }
  return null;
}
