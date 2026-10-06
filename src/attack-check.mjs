// Student self-checks only; these observations are not the judge's verdict.
// Never include tokens, private keys, real names, or note bodies in the result.
export async function runAttackChecks(config) {
  if (config.step !== 3) throw new Error('3단계 인증 API 확인을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try { app = new URL(config.publicAppUrl); } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }

  const options = { redirect: 'error', signal: AbortSignal.timeout(10000) };
  const [apiResponse, publicResponse, identityResponse, homeResponse] = await Promise.all([
    fetch(new URL('/api/notes', app), options),
    fetch(new URL('/data.json', app), options),
    fetch(new URL('/aleph.json', app), options),
    fetch(new URL('/', app), options),
  ]);
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
      deploymentIdentityPresent = identity?.schema === 'aleph.defense.deployment.v1'
        && identity.step === 3 && identity.repoUrl === config.repoUrl
        && /^[a-f0-9]{40}$/iu.test(identity.commit ?? '')
        && deploymentUrl.protocol === 'https:' && deploymentUrl.hostname.endsWith('.vercel.app')
        && deploymentUrl.pathname === '/' && !deploymentUrl.search && !deploymentUrl.hash;
    } catch {}
  }
  const headerPresent = homeResponse.headers.get('x-content-type-options')?.toLowerCase() === 'nosniff'
    || Boolean(homeResponse.headers.get('content-security-policy'));

  return [
    { attackId: 'anonymous_notes_api', expected: '비로그인 목록 요청은 401/403 JSON 오류',
      observed: apiErrorJson ? `비로그인 요청 거부: HTTP ${apiResponse.status}, JSON 오류 문구 확인`
        : `비로그인 JSON 거부 확인 실패: HTTP ${apiResponse.status}` },
    { attackId: 'public_json_empty', expected: '공개 data.json에 메모와 1단계 표시가 없음',
      observed: publicJsonEmpty ? '공개 data.json의 notes가 비어 있고 1단계 표시가 없음'
        : `공개 data.json 비움 확인 실패: HTTP ${publicResponse.status}` },
    { attackId: 'deployment_identity', expected: '배포 주소의 /aleph.json이 3단계 정보를 반환',
      observed: deploymentIdentityPresent ? '/aleph.json에서 저장소·배포 주소·3단계 정보 확인'
        : `/aleph.json 확인 실패: HTTP ${identityResponse.status}` },
    { attackId: 'security_header', expected: '첫 화면에 nosniff 또는 CSP 보안 헤더가 있음',
      observed: headerPresent ? '첫 화면 응답에서 보안 헤더 확인'
        : '첫 화면 응답에 nosniff/CSP 헤더가 없음' },
  ];
}
