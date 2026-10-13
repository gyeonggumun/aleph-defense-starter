// Student self-checks only; these observations are not the judge's verdict.
// Never include tokens, private keys, real names, or note bodies in the result.
import { createHash } from 'node:crypto';

let lastCheckEvidence = [];

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

  const options = { redirect: 'error' };
  const requestCheck = async (attackId, path, init = options) => {
    const url = new URL(path, app);
    const method = String(init.method ?? 'GET').toUpperCase();
    const urlSha256 = createHash('sha256').update(url.href).digest('hex');
    try {
      const response = await fetch(url, {
        ...init,
        signal: init.signal ?? AbortSignal.timeout(10000),
        alephEvidence: { caseId: attackId, requestKey: 'read' },
      });
      const body = await response.arrayBuffer();
      const bodyText = new TextDecoder().decode(body);
      let bodyJson = null;
      try { bodyJson = JSON.parse(bodyText); } catch {}
      const jsonArrayLength = Array.isArray(bodyJson) ? bodyJson.length
        : Array.isArray(bodyJson?.notes) ? bodyJson.notes.length : null;
      const jsonReady = typeof bodyJson?.ready === 'boolean' ? bodyJson.ready : null;
      const checkedAt = new Date().toISOString();
      const requestId = response.headers.get('x-request-id') ?? response.headers.get('x-vercel-id') ?? null;
      const observed = [
        `HTTP ${response.status}`,
        `bodyBytes=${body.byteLength}`,
        `jsonArrayLength=${jsonArrayLength ?? 'null'}`,
        `jsonReady=${jsonReady ?? 'null'}`,
        `method=${method}`,
        `urlSha256=${urlSha256}`,
      ].join('; ');
      lastCheckEvidence.push({ attackId, requestId, checkedAt });
      return { response, checkedAt, attackId, observed };
    } catch {
      lastCheckEvidence.push({ attackId, requestId: null, checkedAt: null });
      return { response: null, checkedAt: null, attackId, observed: 'not_run' };
    }
  };
  const checks = [
    ['anonymous_notes_api', '/api/notes'],
    ['public_json_empty', '/data.json'],
    ['deployment_identity', '/aleph.json'],
    ['security_header', '/'],
    ['browser_supabase_key_absent', '/'],
    ['auth_proxy_restricts_routes', '/api/auth?path=rest%2Fv1%2Fvault_notes', { ...options, method: 'GET' }],
    ...(config.step >= 8 ? [['anonymous_notices_api', '/api/notices']] : []),
    ...(config.step >= 12 ? [['operations_requires_auth', '/api/operations']] : []),
  ];
  const results = [];
  for (const [attackId, path, init] of checks) {
    results.push(await requestCheck(attackId, path, init ?? options));
  }
  const [apiCheck, publicCheck, identityCheck, headerCheck, browserCheck, authProxyCheck,
    noticesCheck, operationsCheck] = results;
  const requestEvidence = check => check?.observed ?? 'not_run';

  const attempts = [
    { attackId: 'anonymous_notes_api', expected: '비로그인 목록 요청은 401/403 JSON 오류',
      observed: requestEvidence(apiCheck) },
    { attackId: 'public_json_empty', expected: '공개 data.json에 메모와 1단계 표시가 없음',
      observed: requestEvidence(publicCheck) },
    { attackId: 'deployment_identity', expected: `/aleph.json에 ${config.step}단계 정보와 허용 경로가 있음`,
      observed: requestEvidence(identityCheck) },
    { attackId: 'security_header', expected: '첫 화면에 nosniff 또는 CSP 보안 헤더가 있음',
      observed: requestEvidence(headerCheck) },
    { attackId: 'browser_supabase_key_absent', expected: '첫 화면 코드에 Supabase API 키가 없음',
      observed: requestEvidence(browserCheck) },
    { attackId: 'auth_proxy_restricts_routes', expected: '인증 중계가 Auth 경로 이외의 요청을 거부',
      observed: requestEvidence(authProxyCheck) },
    ...(config.step >= 8 ? [{ attackId: 'anonymous_notices_api',
      expected: '비로그인 공지 요청은 401/403 JSON 오류',
      observed: requestEvidence(noticesCheck) }] : []),
    ...(config.step >= 7 ? [{ attackId: 'step_up_live_block',
      expected: '같은 로그인으로 다시 확인하기 전에는 복합 위험 요청에서 자료가 없음',
      observed: 'not_run' }] : []),
    ...(config.step >= 10 ? [{ attackId: 'verified_backup_restore',
      expected: '검증된 사본으로 시험 정책과 B의 메모 한 건만 복구하고 정상·금지 요청을 재시험',
      observed: 'not_run' }] : []),
    ...(config.step >= 11 ? [{ attackId: 'device_approval_live',
      expected: '승인 전 자료 없음, 승인된 기기의 WebAuthn 확인 뒤 정상 화면',
      observed: 'not_run' }] : []),
    ...(config.step >= 12 ? [{ attackId: 'operations_requires_auth',
      expected: '/api/operations는 로그인 전 401 JSON과 요청 ID를 반환',
      observed: requestEvidence(operationsCheck) }] : []),
  ];
  const recordedIds = new Set(lastCheckEvidence.map(item => item.attackId));
  for (const attempt of attempts) {
    if (!recordedIds.has(attempt.attackId)) {
      lastCheckEvidence.push({ attackId: attempt.attackId, requestId: null, checkedAt: null });
    }
  }
  const evidenceById = new Map(lastCheckEvidence.map(item => [item.attackId, item]));
  lastCheckEvidence = attempts.map(item => evidenceById.get(item.attackId));
  return attempts;
}
