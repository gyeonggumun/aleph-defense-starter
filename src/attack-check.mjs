// Student self-checks only; these observations are not the judge's verdict.
// Never include tokens, private keys, real names, or note bodies in the result.
export async function runAttackChecks(config) {
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
  const requestCheck = (attackId, path, init = options) => {
    const url = new URL(path, app);
    const checkedAt = new Date().toISOString();
    return fetch(url, {
      ...init,
      signal: init.signal ?? AbortSignal.timeout(10000),
      alephEvidence: { caseId: attackId, requestKey: 'read' },
    }).then(response => ({ response, checkedAt, attackId }));
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
  const apiResponse = apiCheck.response;
  const publicResponse = publicCheck.response;
  const identityResponse = identityCheck.response;
  const homeResponse = headerCheck.response;
  const browserResponse = browserCheck.response;
  const authProxyResponse = authProxyCheck.response;
  const noticesResponse = noticesCheck?.response ?? null;
  const operationsResponse = operationsCheck?.response ?? null;
  const requestEvidence = check => {
    if (!check) return 'not_run';
    const response = check.response;
    const requestId = response.headers.get('x-request-id') ?? response.headers.get('x-vercel-id') ?? '없음';
    return `attackId=${check.attackId}; HTTP ${response.status}; 요청 ID ${requestId}; UTC ${check.checkedAt}`;
  };
  let apiErrorJson = false;
  if ([401, 403].includes(apiResponse.status)
      && /application\/(?:[a-z.+-]*\+)?json/iu.test(apiResponse.headers.get('content-type') ?? '')) {
    try {
      const result = await apiResponse.json();
      apiErrorJson = typeof result?.error === 'string' && Boolean(result.error);
    } catch {}
  }
  let publicJsonEmpty = false;
  if (publicResponse.ok) {
    try {
      const data = await publicResponse.json();
      publicJsonEmpty = Array.isArray(data?.notes) && data.notes.length === 0
        && !JSON.stringify(data).includes(config.sampleMarker);
    } catch {}
  }
  let deploymentIdentityPresent = false;
  if (identityResponse.ok) {
    try {
      const identity = await identityResponse.json();
      const deploymentUrl = new URL(identity?.publicAppUrl);
      const originalApiUrl = new URL(identity?.originalApiUrl);
      deploymentIdentityPresent = identity?.schema === 'aleph.defense.deployment.v1'
        && identity.step === config.step && identity.repoUrl === config.repoUrl
        && JSON.stringify(identity.allowedRoutes) === JSON.stringify(config.allowedRoutes)
        && Array.isArray(identity.allowedRoutes) && identity.allowedRoutes.length > 0
        && identity.originalApiUrl === config.originalApiUrl
        && originalApiUrl.protocol === 'https:' && !originalApiUrl.username && !originalApiUrl.password
        && !originalApiUrl.search && !originalApiUrl.hash
        && /^[a-f0-9]{40}$/iu.test(identity.commit ?? '')
        && deploymentUrl.protocol === 'https:' && deploymentUrl.hostname.endsWith('.vercel.app')
        && deploymentUrl.pathname === '/' && !deploymentUrl.search && !deploymentUrl.hash;
    } catch {}
  }
  const headerPresent = homeResponse.headers.get('x-content-type-options')?.toLowerCase() === 'nosniff'
    || Boolean(homeResponse.headers.get('content-security-policy'));
  let browserSupabaseKeyAbsent = false;
  if (browserResponse.ok) {
    try {
      const source = await browserResponse.text();
      browserSupabaseKeyAbsent = !/sb_(?:publishable|secret)_[A-Za-z0-9_-]+/iu.test(source)
        && !/\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b/u.test(source);
    } catch {}
  }
  let authProxyClosed = false;
  if (authProxyResponse.status === 404
      && /application\/(?:[a-z.+-]*\+)?json/iu.test(authProxyResponse.headers.get('content-type') ?? '')) {
    try {
      const result = await authProxyResponse.json();
      authProxyClosed = result?.error === 'NOT_FOUND';
    } catch {}
  }

  let operationsAuthRequired = false;
  if (config.step >= 12 && operationsResponse
      && operationsResponse.status === 401
      && /application\/(?:[a-z.+-]*\+)?json/iu.test(operationsResponse.headers.get('content-type') ?? '')) {
    try {
      const result = await operationsResponse.json();
      operationsAuthRequired = result?.error === 'UNAUTHORIZED'
        && typeof result?.requestId === 'string' && typeof result?.checkedAt === 'string';
    } catch {}
  }

  return [
    { attackId: 'anonymous_notes_api', expected: '비로그인 목록 요청은 401/403 JSON 오류',
      observed: `${apiErrorJson ? '비로그인 요청 거부, JSON 오류 문구 확인' : '비로그인 JSON 거부 확인 실패'}; ${requestEvidence(apiCheck)}` },
    { attackId: 'public_json_empty', expected: '공개 data.json에 메모와 1단계 표시가 없음',
      observed: `${publicJsonEmpty ? '공개 data.json의 notes가 비어 있고 1단계 표시가 없음' : '공개 data.json 비움 확인 실패'}; ${requestEvidence(publicCheck)}` },
    { attackId: 'deployment_identity', expected: `/aleph.json에 ${config.step}단계 정보와 허용 경로가 있음`,
      observed: `${deploymentIdentityPresent ? `/aleph.json에서 저장소·배포 주소·${config.step}단계 정보·허용 경로 확인` : '/aleph.json 확인 실패'}; ${requestEvidence(identityCheck)}` },
    { attackId: 'security_header', expected: '첫 화면에 nosniff 또는 CSP 보안 헤더가 있음',
      observed: `${headerPresent ? '첫 화면 응답에서 보안 헤더 확인' : '첫 화면 응답에 nosniff/CSP 헤더가 없음'}; ${requestEvidence(headerCheck)}` },
    { attackId: 'browser_supabase_key_absent', expected: '첫 화면 코드에 Supabase API 키가 없음',
      observed: `${browserSupabaseKeyAbsent ? '첫 화면 코드에 Supabase API 키 없음' : '첫 화면 코드에 Supabase API 키가 있거나 확인 실패'}; ${requestEvidence(browserCheck)}` },
    { attackId: 'auth_proxy_restricts_routes', expected: '인증 중계가 Auth 경로 이외의 요청을 거부',
      observed: `${authProxyClosed ? '인증 중계가 데이터 경로 요청을 JSON 404로 거부' : '인증 중계 외부 경로 거부 확인 실패'}; ${requestEvidence(authProxyCheck)}` },
    ...(config.step >= 8 ? [{ attackId: 'anonymous_notices_api',
      expected: '비로그인 공지 요청은 401/403 JSON 오류',
      observed: `${[401, 403].includes(noticesResponse.status)
        && /json/iu.test(noticesResponse.headers.get('content-type') ?? '')
        ? '비로그인 공지 요청 거부' : '비로그인 공지 JSON 거부 확인 실패'}; ${requestEvidence(noticesCheck)}` }] : []),
    ...(config.step >= 7 ? [{ attackId: 'step_up_live_block',
      expected: '같은 로그인으로 다시 확인하기 전에는 복합 위험 요청에서 자료가 없음',
      observed: 'not_run: 운영 엔진의 같은 로그인 재인증 시각 검증 계약과 실측 요청이 제공되지 않음' }] : []),
    ...(config.step >= 10 ? [{ attackId: 'verified_backup_restore',
      expected: '검증된 사본으로 시험 정책과 B의 메모 한 건만 복구하고 정상·금지 요청을 재시험',
      observed: 'not_run: 침해 전 검증된 정책·메모 사본과 B 소유 메모가 제공되지 않음' }] : []),
    ...(config.step >= 11 ? [{ attackId: 'device_approval_live',
      expected: '승인 전 자료 없음, 승인된 기기의 WebAuthn 확인 뒤 정상 화면',
      observed: 'not_run: 승인된 실기기 등록과 관리자 승인은 별도 사용자 절차가 필요함' }] : []),
    ...(config.step >= 12 ? [{ attackId: 'operations_requires_auth',
      expected: '/api/operations는 로그인 전 401 JSON과 요청 ID를 반환',
      observed: `${operationsAuthRequired ? '작전실 API가 비로그인 요청을 JSON 401로 거부하고 응답 요청 ID를 반환' : `작전실 API 비로그인 거부 확인 실패: HTTP ${operationsResponse?.status ?? '응답 없음'}`}; ${requestEvidence(operationsCheck)}` }] : []),
  ];
}
