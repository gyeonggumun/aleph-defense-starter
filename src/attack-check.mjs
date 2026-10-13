// Student self-checks only; these observations are not the judge's verdict.
// Never include tokens, private keys, real names, or note bodies in the result.
let lastCheckEvidence = [];

function newRequestKey() {
  const generated = globalThis.crypto?.randomUUID?.();
  if (generated) return generated;
  return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}-${Math.random().toString(36).slice(2)}`;
}

export function getLastCheckEvidence() {
  return lastCheckEvidence.map(({ attackId, requestId, checkedAt }) => ({ attackId, requestId, checkedAt }));
}

export async function runAttackChecks(config) {
  lastCheckEvidence = [];
  if (![5, 6, 7, 8, 9, 10, 11, 12].includes(config.step)) throw new Error('5~12단계 인증 API 확인을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try { app = new URL(config.publicAppUrl); } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  const requestCheck = async ({ attackId, path, method = 'GET', matches }) => {
    if (!['GET', 'HEAD'].includes(method) || requestCount >= 24) {
      return { attackId, requestId: null, checkedAt: null, observed: 'not_run', result: 'not_run' };
    }
    const url = new URL(path, app);
    const requestKey = newRequestKey();
    let response;
    try {
      requestCount += 1;
      response = await fetch(url, {
        method, redirect: 'error', signal: AbortSignal.timeout(10000),
        headers: { accept: 'application/json' },
        alephEvidence: { caseId: attackId, requestKey },
      });
    } catch {
      return { response: null, checkedAt: null, attackId, requestId: null,
        observed: 'not_run', result: 'not_run' };
    }
    let bodyText = '';
    let bodyReadable = false;
    try {
      bodyText = await response.text();
      bodyReadable = true;
    } catch {}
    let bodyJson = null;
    try { bodyJson = JSON.parse(bodyText); } catch {}
    const jsonReady = typeof bodyJson?.ready === 'boolean' ? bodyJson.ready : null;
    const checkedAt = new Date().toISOString();
    const requestId = requestKey;
    const fields = [`HTTP ${response.status}`];
    if (jsonReady !== null) fields.push(`jsonReady=${jsonReady}`);
    const observed = fields.join('; ');
    const ran = { response, bodyText, bodyJson, bodyReadable, checkedAt, attackId, requestId, observed };
    return { ...ran, result: matches(ran) ? 'blocked' : 'breached' };
  };
  const checks = [
    { attackId: 'anonymous_notes_api', stage: 3, path: '/api/notes',
      expected: '비로그인 목록 요청은 401/403 JSON 오류',
      matches: r => r.bodyReadable && [401, 403].includes(r.response.status)
        && typeof r.bodyJson?.error === 'string' },
    { attackId: 'public_json_empty', stage: 2, path: '/data.json',
      expected: '공개 data.json에 메모가 없음',
      matches: r => r.bodyReadable && r.response.status === 200
        && (Array.isArray(r.bodyJson) ? r.bodyJson.length === 0
        : Array.isArray(r.bodyJson?.notes) && r.bodyJson.notes.length === 0) },
    { attackId: 'deployment_identity', stage: 12, path: '/aleph.json',
      expected: `/aleph.json에 ${config.step}단계 정보와 허용 경로가 있음`,
      matches: r => r.bodyReadable && r.response.status === 200 && r.bodyJson?.step === config.step
        && Array.isArray(r.bodyJson?.allowedRoutes) && r.bodyJson.allowedRoutes.length > 0 },
    { attackId: 'security_header', stage: 2, path: '/',
      expected: '첫 화면에 nosniff 또는 CSP 보안 헤더가 있음',
      matches: r => r.response.status === 200
        && (r.response.headers.get('x-content-type-options')?.toLowerCase() === 'nosniff'
          || Boolean(r.response.headers.get('content-security-policy'))) },
    { attackId: 'browser_supabase_key_absent', stage: 5, path: '/',
      expected: '첫 화면 응답에 Supabase 공개 키가 없음',
      matches: r => r.bodyReadable && r.response.status === 200
        && !/\b(?:sb_publishable|sb_anon)_[A-Za-z0-9_-]+|SUPABASE_(?:ANON|PUBLISHABLE)_KEY\s*=/iu.test(r.bodyText) },
    { attackId: 'auth_proxy_restricts_routes', stage: 5, path: '/api/auth?path=rest%2Fv1%2Fvault_notes',
      expected: '인증 중계가 Auth 경로 이외의 요청을 거부',
      matches: r => r.bodyReadable && [401, 403, 404].includes(r.response.status)
        && !/"(?:title|body|content)"\s*:/u.test(r.bodyText) },
    ...(config.step >= 8 ? [{ attackId: 'anonymous_notices_api', stage: 8, path: '/api/notices',
      expected: '비로그인 공지 요청은 401/403 JSON 오류',
      matches: r => r.bodyReadable && [401, 403].includes(r.response.status)
        && typeof r.bodyJson?.error === 'string' }] : []),
    ...(config.step >= 12 ? [{ attackId: 'operations_requires_auth', stage: 12, path: '/api/operations',
      expected: '/api/operations는 로그인 전 401 JSON과 요청 ID를 반환',
      matches: r => r.bodyReadable && r.response.status === 401
        && typeof r.bodyJson?.error === 'string' }] : []),
    ...(config.step >= 12 ? [
      { attackId: 'legacy_static_copy', stage: 1, path: '/public/data.json',
        expected: '이전 public 경로는 공개 메모를 반환하지 않음',
        matches: r => r.bodyReadable && r.response.status === 404 },
      { attackId: 'anonymous_other_note', stage: 4,
        path: '/api/notes/00000000-0000-4000-8000-000000000001',
        expected: '무인증 단건 메모 요청은 JSON 401/403',
        matches: r => r.bodyReadable && [401, 403].includes(r.response.status)
          && typeof r.bodyJson?.error === 'string' },
      ...[
        ['device_registration', 6, '학생 기기 규칙: 정상 허용·미등록 거부'],
        ['normal_access', 7, '학생 판정기: 정상 합성 요청 허용'],
        ['step_up', 7, '학생 판정기: 복합 위험 추가 확인·새 로그인 허용'],
        ['resource_zones', 8, '학생 구역 규칙: 정확한 경로 허용·금지 경로와 수정 거부'],
        ['detection_normal', 9, '학생 탐지기: 정상·경계 사건은 회수 제안 없음'],
        ['detection_burst', 9, '학생 탐지기: 계약상 폭주 사건은 회수 제안'],
        ['policy_restore_guard', 10, '합성 정책 검증: 잘못된 사본 거부·다른 규칙 보존'],
      ].map(([caseId, stage, expected]) => ({
        attackId: `rule_${caseId}`, stage, expected,
        path: `/api/checks?case=${caseId}`,
        matches: r => r.bodyReadable && r.response.status === 200 && r.bodyJson?.ready === true
          && r.bodyJson?.caseId === caseId && r.bodyJson?.engineEnforced === 'not_run',
      })),
    ] : []),
  ];
  let requestCount = 0;
  const results = [];
  for (const check of checks) results.push({ ...check, ...(await requestCheck(check)) });
  const notRun = [
    ...(config.step >= 7 ? [{ attackId: 'step_up_live_block', stage: 7,
      expected: '재로그인 전에는 복합 위험 요청에서 자료 없음' }] : []),
    ...(config.step >= 10 ? [{ attackId: 'verified_backup_restore', stage: 10,
      expected: '검증한 사본으로 정책과 지정 메모만 복구' }] : []),
    ...(config.step >= 11 ? [{ attackId: 'device_approval_live', stage: 11,
      expected: '승인된 기기의 WebAuthn 확인 뒤 자료 접근' }] : []),
  ].map(item => ({ ...item, observed: 'not_run', result: 'not_run', requestId: null, checkedAt: null }));
  const attempts = [...results, ...notRun].map(({ attackId, stage, expected, observed, result }) => ({
    attackId, stage, expected, observed, result,
  }));
  const evidenceById = new Map(results.map(item => [item.attackId, {
    attackId: item.attackId, requestId: item.requestId, checkedAt: item.checkedAt,
  }]));
  lastCheckEvidence = attempts.map(item => evidenceById.get(item.attackId)
    ?? { attackId: item.attackId, requestId: null, checkedAt: null });
  return attempts;
}
