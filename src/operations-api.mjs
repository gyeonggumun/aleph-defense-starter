import { randomUUID } from 'node:crypto';
import config from '../aleph.config.json' with { type: 'json' };
import { RULE_IDS, decide } from './decider.mjs';
import { deviceApproved } from './device-approval.mjs';
import { noteBackupStatus } from './restore-note.mjs';
import { getStage12CheckReport } from './stage12-checks.mjs';

function respond(response, status, payload) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  if (payload.requestId) response.setHeader('X-Request-Id', payload.requestId);
  return response.status(status).json(payload);
}

function decisionRequest({ registered, requestId }) {
  return {
    schema: 'aleph.decision.v1', requestId, classId: 'stage12_fixture',
    projectId: 'stage12_fixture', subjectId: 'redacted_fixture', deviceId: 'a'.repeat(16),
    service: 'notes', method: 'GET', path: '/api/my/notes', route: 'GET /api/my/notes',
    queryLength: 0, querySha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    at: new Date().toISOString(), policyRevision: 12, deviceRegistered: registered,
    stepUp: { verified: false, authAgeSeconds: null }, recentEvents: [],
    signals: { source: 'none', region: 'unknown', network: 'unknown', hour: null },
  };
}

function summarizeDeviceStatuses(rows) {
  const counts = { approved: 0, pending: 0, revoked: 0, other: 0 };
  for (const row of rows ?? []) {
    if (Object.hasOwn(counts, row?.status)) counts[row.status] += 1;
    else counts.other += 1;
  }
  return counts;
}

export async function handleOperationsRequest(request, response, suppliedContext, settings = process.env) {
  const requestId = randomUUID();
  let checkedAt = new Date().toISOString();
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return respond(response, 405, { error: 'METHOD_NOT_ALLOWED', requestId, checkedAt });
  }

  let context;
  try { context = suppliedContext ?? (await import('./notes-api.mjs')).getServices(); } catch {
    return respond(response, 503, { error: 'OPERATIONS_STATUS_UNAVAILABLE', requestId, checkedAt });
  }
  let identity;
  try { identity = await context.verifyLogin(request.headers?.authorization); } catch {}
  if (!identity) return respond(response, 401, { error: 'UNAUTHORIZED', requestId, checkedAt });
  if (!await (context.deviceApproved ?? deviceApproved)(context.database, identity,
    request.headers?.['x-device-grant'])) {
    return respond(response, 403, { error: 'DEVICE_NOT_APPROVED', requestId, checkedAt });
  }

  try {
    const [noteCount, deviceRows, submissionChecks] = await Promise.all([
      context.database.from('vault_notes').select('id', { count: 'exact', head: true })
        .eq('owner_id', identity.userId),
      context.database.from('device_credentials').select('status').eq('owner_id', identity.userId),
      getStage12CheckReport(settings),
    ]);
    if (noteCount.error || deviceRows.error) throw new Error('status_query_failed');

    const normalInput = decisionRequest({ registered: true, requestId: randomUUID() });
    const deniedInput = decisionRequest({ registered: false, requestId: randomUUID() });
    const [normalDecision, deniedDecision] = await Promise.all([decide(normalInput), decide(deniedInput)]);
    const deviceStatus = summarizeDeviceStatuses(deviceRows.data);
    const backupStatus = noteBackupStatus(settings);
    checkedAt = new Date().toISOString();
    const commit = /^[a-f0-9]{40}$/iu.test(settings.VERCEL_GIT_COMMIT_SHA ?? '')
      ? settings.VERCEL_GIT_COMMIT_SHA.slice(0, 12).toLowerCase() : 'unknown';
    const records = [
      { area: '판정기', test: '등록 기기 정상 가상 요청', expected: 'allow', actual: normalDecision.decision,
        reasonCode: normalDecision.reasonCode, requestId: normalDecision.requestId, checkedAt, source: '학생 판정기 가상 입력 · 운영 엔진 기록 아님' },
      { area: '판정기', test: '미등록 기기 거부 가상 요청', expected: 'deny / device_not_registered',
        actual: `${deniedDecision.decision} / ${deniedDecision.reasonCode}`,
        requestId: deniedDecision.requestId, checkedAt, source: '학생 판정기 가상 입력 · 운영 엔진 기록 아님' },
      { area: '탐지', test: '실제 운영 사건 스트림', expected: '연결된 사건만 판정',
        actual: 'not_run', reasonCode: 'LIVE_EVENT_FEED_NOT_CONNECTED',
        requestId, checkedAt, source: '서버 연결 상태 조회' },
      { area: '회수', test: '현재 사용자 기기 상태', expected: '서버 저장 상태 요약',
        actual: deviceStatus, requestId, checkedAt, source: 'device_credentials 상태 조회' },
      { area: '복구', test: '메모 백업 검증 상태', expected: '사전 고정 해시·소유자 검증',
        actual: backupStatus.status, reasonCode: backupStatus.reasonCode,
        requestId, checkedAt, source: '서버 환경의 비공개 백업 메타데이터' },
      { area: '자료', test: '현재 사용자 메모 건수', expected: '본문·ID를 제외한 서버 COUNT',
        actual: Number.isInteger(noteCount.count) ? noteCount.count : null,
        requestId, checkedAt, source: 'vault_notes COUNT 조회' },
    ];
    if (submissionChecks) {
      records.push(...submissionChecks.attempts.map(attempt => ({
        area: '제출 점검', test: attempt.attackId, expected: attempt.expected,
        actual: attempt.observed, requestId: attempt.requestId, checkedAt: attempt.checkedAt,
        source: itemSource(attempt.attackId, submissionChecks.commit),
      })));
    }
    const submissionCheckSummary = {
      status: 'available', checkedAt: submissionChecks.checkedAt, commit: submissionChecks.commit,
      total: submissionChecks.total, blocked: submissionChecks.blocked, failed: submissionChecks.failed,
      executed: submissionChecks.executed, notRun: submissionChecks.notRun,
    };

    return respond(response, 200, {
      schema: 'aleph.operations.v1', requestId, checkedAt,
      submissionChecks: submissionCheckSummary,
      deployment: { step: config.step, commit },
      decider: { source: 'src/decider.mjs', rules: [...RULE_IDS],
        engineRuntime: 'unverified', engineNote: '이 API는 ALEPH SDP 엔진의 감사 결과를 읽지 않습니다.' },
      detection: { source: 'src/detect.mjs', liveEventFeed: 'not_connected', eventCount: null,
        status: 'not_run', liveEventNote: '실제 엔진 사건 스트림 계약이 없어 운영 사건은 미실행입니다.' },
      assaultSuiteNote: '41종 공격 전체는 심판이 실행합니다. 이 보고서는 전체 시험의 통과를 나타내지 않습니다.',
      revocation: { deviceStatus, actualRevocation: 'not_executed',
        note: '탐지 결과는 제안일 뿐이며 이 API는 기기 권한을 변경하지 않습니다.' },
      restore: { policySnapshot: { status: 'unavailable', reasonCode: 'VERIFIED_POLICY_SNAPSHOT_UNAVAILABLE' },
        noteBackup: backupStatus, version: commit },
      dataSummary: { ownNoteCount: Number.isInteger(noteCount.count) ? noteCount.count : null,
        noteBodiesIncluded: false },
      records,
    });
  } catch {
    return respond(response, 502, { error: 'OPERATIONS_STATUS_UNAVAILABLE', requestId, checkedAt });
  }
}

function itemSource(attackId, commit) {
  return attackId.startsWith('rule_')
    ? `학생 코드 합성 시험의 HTTP 응답 · ALEPH SDP 엔진 집행 미실행 · 커밋 ${commit ?? '확인 불가'}`
    : `실제 HTTP 점검 · 커밋 ${commit ?? '확인 불가'}`;
}
