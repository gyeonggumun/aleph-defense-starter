// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 엔진이 확인한 등록 기기의 자료실 읽기만 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.

export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'xdr.brute_force_source_ip', 'xdr.web_injection_source_ip', 'step_up_required', 'resource.own_note', 'resource.instructor_notice']);

const ITEM = /^[a-zA-Z0-9_-]{1,128}$/u;
const PRACTICE_BINDINGS = [
  ['demo', 'learner_fixture'],
].map(([id, subjectId]) => ({
  subjectId, classId: 'class_fixture', projectId: 'project_fixture',
  deviceId: 'aaaaaaaaaaaaaaaa', service: 'notes', path: `/notes/${id}`,
  resourceId: `note:${id}`, ownerSubjectId: subjectId, permissions: ['GET', 'PUT'],
}));

function resourceBindings() {
  const raw = typeof process !== 'undefined' ? process.env?.ALEPH_RESOURCE_BINDINGS : undefined;
  if (raw === undefined) return PRACTICE_BINDINGS;
  try {
    const entries = JSON.parse(raw);
    if (!Array.isArray(entries)) return [];
    return entries.filter(entry => entry && typeof entry === 'object' && !Array.isArray(entry)
      && ['subjectId', 'classId', 'projectId', 'deviceId', 'service', 'path', 'resourceId']
        .every(key => typeof entry[key] === 'string' && entry[key].length > 0)
      && Array.isArray(entry.permissions) && entry.permissions.length > 0
      && entry.permissions.every(method => ['GET', 'PUT'].includes(method)));
  } catch {
    return [];
  }
}

function resourceAllowed(request, resource) {
  if (!resource || request?.schema !== 'aleph.decision.v1'
      || typeof request.subjectId !== 'string' || !request.subjectId) return false;
  // Collection reads are filtered by owner in the API; notices are readable by students.
  if (resource.zone === 'own_notes' || request.method === 'GET'
      && resource.zone === 'instructor_notice') return true;
  return resourceBindings().some(entry => entry?.subjectId === request.subjectId
    && entry.classId === request.classId
    && entry.projectId === request.projectId
    && entry.deviceId === request.deviceId
    && entry.service === request.service
    && entry.path === request.path && entry.resourceId === resource.id
    && Array.isArray(entry.permissions) && entry.permissions.includes(request.method)
    && (resource.zone !== 'own_note' || entry.ownerSubjectId === request.subjectId)
    && (resource.zone !== 'instructor_notice' || entry.instructor === true));
}

// Engine-verified service, method, route, and exact path identify the zone.
// The authenticated API repeats the owner and instructor checks.
export function resourceZone(request) {
  if (request?.service !== 'notes' || typeof request.path !== 'string'
      || request.queryLength !== 0) return null;
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
  if (id.toLowerCase() === 'export') return null;
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

function needsStepUp(request) {
  const signals = request?.signals;
  const events = request?.recentEvents;
  // Only the engine's labeled virtual events have a documented source for these signals.
  if (signals?.source !== 'judge_fixture' || !Number.isInteger(signals.hour)
      || signals.hour < 0 || signals.hour > 23 || !Array.isArray(events)) return false;
  const unusualHour = signals.hour < 6 || signals.hour >= 22;
  const newNetwork = signals.network === 'unusual';
  const manyRecentReads = events.some(event => event?.kind === 'risk_signal'
    && Number.isInteger(event.count) && event.count >= 10
    && Number.isFinite(event.ageSeconds) && event.ageSeconds >= 0 && event.ageSeconds <= 300);
  return unusualHour && newNetwork && manyRecentReads;
}

export async function decide(request) {
  const registered = request?.deviceRegistered === true;
  if (!registered) {
    return { schema: 'aleph.decision.v1', requestId: request?.requestId,
      decision: 'deny', reasonCode: 'device_not_registered', ruleIds: ['device_registered'] };
  }
  const xdrRuleIds = [];
  const source = request?.signals?.source;
  // The documented none/judge_fixture inputs never need local XDR files.
  // Preserve local IP-fixture integration, and fail closed if its store cannot be read.
  if (typeof source === 'string' && /^[0-9a-f:.]+$/iu.test(source) && /[.:]/u.test(source)) {
    try {
      const bruteForce = await import('../xdr/brute-force/ztna-rules.mjs');
      const webInjection = await import('../xdr/web-injection/ztna-rules.mjs');
      if (await bruteForce.activeDenyRuleFor(source)) xdrRuleIds.push(RULE_IDS[2]);
      if (await webInjection.activeDenyRuleFor(source)) xdrRuleIds.push(RULE_IDS[3]);
    } catch {
      return { schema: 'aleph.decision.v1', requestId: request?.requestId,
        decision: 'deny', reasonCode: 'starter_not_ready', ruleIds: [RULE_IDS[0]] };
    }
  }
  const resource = resourceZone(request);
  const vaultRead = Boolean(resource && request.method === 'GET');
  const allowedZone = resourceAllowed(request, resource);
  const resourceRuleId = resource?.zone === 'instructor_notice' ? RULE_IDS[6] : RULE_IDS[5];
  const complexRisk = registered && vaultRead && needsStepUp(request);
  const recentVerifiedLogin = request?.stepUp?.verified === true
    && Number.isInteger(request.stepUp.authAgeSeconds)
    && request.stepUp.authAgeSeconds >= 0 && request.stepUp.authAgeSeconds <= 300;
  const decision = !registered || xdrRuleIds.length || !allowedZone ? 'deny'
    : complexRisk && !recentVerifiedLogin ? 'step_up' : 'allow';
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision,
    reasonCode: !registered ? 'device_not_registered' : decision === 'step_up' ? 'step_up_required'
      : decision === 'allow' ? 'approved' : 'starter_not_ready',
    ruleIds: !registered ? [RULE_IDS[1], ...xdrRuleIds]
      : xdrRuleIds.length ? xdrRuleIds : !allowedZone ? [RULE_IDS[0],
        ...(resource?.zone === 'instructor_notice' ? [RULE_IDS[6]] : [])]
        : complexRisk ? [RULE_IDS[1], RULE_IDS[4], resourceRuleId]
          : [RULE_IDS[1], resourceRuleId],
  };
}
