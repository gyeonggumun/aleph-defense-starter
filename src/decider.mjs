// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 엔진이 확인한 등록 기기의 자료실 읽기만 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.

export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'xdr.brute_force_source_ip', 'xdr.web_injection_source_ip', 'step_up_required', 'resource.own_note', 'resource.instructor_notice']);

const ITEM_PATHS = Object.freeze({
  'GET /api/notes/:id': /^\/api\/notes\/(?!\.{1,2}$)[^/?#%\\\x00-\x1f]+$/u,
  'GET /notes/:id': /^\/notes\/(?!\.{1,2}$)[^/?#%\\\x00-\x1f]+$/u,
  'GET /api/notices/:id': /^\/api\/notices\/(?!\.{1,2}$)[^/?#%\\\x00-\x1f]+$/u,
  'GET /notices/:id': /^\/notices\/(?!\.{1,2}$)[^/?#%\\\x00-\x1f]+$/u,
});
const RESERVED_RESOURCES = new Set(['export', 'backup', 'restore', 'admin', 'all', 'upload']);

function resourceAllowed(request, resource) {
  if (!resource || request?.schema !== 'aleph.decision.v1'
      || request.service !== 'notes' || request.method !== 'GET'
      || request.queryLength !== 0
      || typeof request.subjectId !== 'string' || !request.subjectId) return false;
  // Every allowed read has an exact path/route pair; the notes API rechecks stored ownership.
  return ['own_notes', 'own_note', 'instructor_notice'].includes(resource.zone);
}

// Engine-verified service, method, route, and exact path identify the zone.
// The authenticated API repeats the owner and instructor checks.
export function resourceZone(request) {
  if (request?.service !== 'notes' || request.method !== 'GET'
      || typeof request.path !== 'string' || request.queryLength !== 0) return null;
  if (request.path === '/api/my/notes' && request.route === 'GET /api/my/notes') {
    return { id: 'notes:collection', zone: 'own_notes' };
  }
  if (request.path === '/api/notices' && request.route === 'GET /api/notices') {
    return { id: 'notices:collection', zone: 'instructor_notice' };
  }
  for (const [route, pattern] of Object.entries(ITEM_PATHS)) {
    if (request.route !== route || !pattern.test(request.path)) continue;
    const id = request.path.split('/').at(-1);
    if (RESERVED_RESOURCES.has(id.toLowerCase())) return null;
    const isNotice = request.path.includes('/notices/');
    return { id: `${isNotice ? 'notice' : 'note'}:${id}`,
      zone: isNotice ? 'instructor_notice' : 'own_note' };
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
