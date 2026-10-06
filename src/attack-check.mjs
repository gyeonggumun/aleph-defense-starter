// The student changes this check as each stage adds an attack to the same app.
// Never return tokens, private keys, real names, or note bodies.
export async function runAttackChecks(config) {
  if (config.step !== 2) throw new Error('2단계 자료 API 확인을 src/attack-check.mjs에 구현해 주세요.');
  let app;
  try {
    app = new URL(config.publicAppUrl);
  } catch {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (app.protocol !== 'https:' || app.username || app.password || app.search || app.hash
      || app.pathname !== '/' || app.hostname.endsWith('.example')) {
    throw new Error('aleph.config.json의 실제 배포 주소를 먼저 넣어 주세요.');
  }
  if (typeof config.sampleMarker !== 'string' || !config.sampleMarker) throw new Error('가상 메모의 확인 표시를 넣어 주세요.');
  const apiResponse = await fetch(new URL('/api/notes', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let apiNotesVisible = false;
  if (apiResponse.ok) {
    try {
      const data = await apiResponse.json();
      apiNotesVisible = data?.sampleMarker === config.sampleMarker && Array.isArray(data.notes)
        && data.notes.length === 4 && data.notes.every(note => typeof note.title === 'string'
          && typeof note.content === 'string');
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  const publicResponse = await fetch(new URL('/data.json', app), {
    redirect: 'error', signal: AbortSignal.timeout(10000),
  });
  let publicJsonEmpty = false;
  if (publicResponse.ok) {
    try {
      const data = await publicResponse.json();
      publicJsonEmpty = Array.isArray(data?.notes) && data.notes.length === 0;
    } catch {
      // A non-JSON response is a failed check, not a successful deployment.
    }
  }
  return [
    { attackId: 'anonymous_notes_api', expected: '비로그인 서버 API에서 가상 메모 네 건 확인',
      observed: apiNotesVisible ? '비로그인 요청에서 가상 메모 네 건 확인'
        : `비로그인 API에서 네 건을 확인하지 못함 (HTTP ${apiResponse.status})` },
    { attackId: 'public_json_empty', expected: '공개 data.json에 메모가 없음',
      observed: publicJsonEmpty ? '공개 data.json의 notes가 비어 있음'
        : `공개 data.json이 비어 있지 않거나 확인할 수 없음 (HTTP ${publicResponse.status})` },
  ];
}
