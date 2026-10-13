import { createHash, randomUUID } from 'node:crypto';
import { decide } from './decider.mjs';
import { detect } from './detect.mjs';
import { planPolicyRestore } from '../scripts/recover-policy.mjs';

export const RULE_CHECK_CASES = Object.freeze([
  'device_registration', 'normal_access', 'step_up', 'resource_zones',
  'detection_normal', 'detection_burst', 'policy_restore_guard',
]);

function input(overrides = {}) {
  return {
    schema: 'aleph.decision.v1', requestId: randomUUID(),
    classId: 'stage12_fixture', projectId: 'stage12_fixture', subjectId: 'learner_fixture',
    deviceId: 'a'.repeat(16), service: 'notes', method: 'GET',
    path: '/api/my/notes', route: 'GET /api/my/notes', queryLength: 0,
    querySha256: createHash('sha256').update('').digest('hex'),
    at: new Date().toISOString(), policyRevision: 12, deviceRegistered: true,
    stepUp: { verified: false, authAgeSeconds: null }, recentEvents: [],
    signals: { source: 'none', region: 'unknown', network: 'unknown', hour: null },
    ...overrides,
  };
}

function events(count) {
  return Array.from({ length: count }, (_, index) => ({
    at: new Date(Date.UTC(2026, 9, 1) + index * 1000).toISOString(),
    method: 'GET', identity: { sub: 'learner_fixture' },
  }));
}

// Executes the student's code with synthetic inputs. Never mutates live policy, data or devices.
export async function runStage12RuleCheck(caseId, dependencies = {}) {
  if (!RULE_CHECK_CASES.includes(caseId)) return null;
  const decideRequest = dependencies.decide ?? decide;
  const detectEvents = dependencies.detect ?? detect;
  const restorePlan = dependencies.planPolicyRestore ?? planPolicyRestore;
  let ready = false;
  let outcomes;
  let source = '학생 판정기 src/decider.mjs · 합성 입력';
  const normal = input();
  if (caseId === 'device_registration') {
    const allowed = await decideRequest(normal);
    const denied = await decideRequest(input({ deviceRegistered: false }));
    outcomes = { normal: allowed.decision, unregistered: denied.decision,
      reasonCode: denied.reasonCode };
    ready = allowed.decision === 'allow' && denied.decision === 'deny'
      && denied.reasonCode === 'device_not_registered';
  } else if (caseId === 'normal_access') {
    const result = await decideRequest(normal);
    outcomes = { normal: result.decision };
    ready = result.decision === 'allow';
  } else if (caseId === 'step_up') {
    const risk = { signals: { source: 'judge_fixture', region: 'unknown', network: 'unusual', hour: 2 },
      recentEvents: [{ kind: 'risk_signal', ageSeconds: 10, count: 20 }] };
    const before = await decideRequest(input(risk));
    const after = await decideRequest(input({ ...risk, stepUp: { verified: true, authAgeSeconds: 60 } }));
    outcomes = { before: before.decision, after: after.decision };
    ready = before.decision === 'step_up' && after.decision === 'allow';
  } else if (caseId === 'resource_zones') {
    const own = await decideRequest(normal);
    const unknown = await decideRequest(input({ path: '/api/admin/notes', route: 'GET /api/admin/notes' }));
    const reserved = await decideRequest(input({ path: '/api/notes/export', route: 'GET /api/notes/:id' }));
    const noticeWrite = await decideRequest(input({ method: 'PUT', path: '/api/notices/fixture',
      route: 'PUT /api/notices/:id' }));
    outcomes = { normal: own.decision, unknown: unknown.decision,
      reserved: reserved.decision, noticeWrite: noticeWrite.decision };
    ready = own.decision === 'allow'
      && [unknown, reserved, noticeWrite].every(result => result.decision === 'deny');
  } else if (caseId.startsWith('detection_')) {
    source = '학생 탐지 규칙 src/detect.mjs · 합성 사건';
    const result = detectEvents(events(caseId === 'detection_normal' ? 120 : 121));
    outcomes = { action: result.action, reasonCode: result.reasonCode ?? null };
    ready = caseId === 'detection_normal' ? result.action === 'observe'
      : result.action === 'propose_revocation' && result.reasonCode === 'burst_read';
  } else {
    source = '학생 복구 절차 scripts/recover-policy.mjs · 합성 사본';
    const backup = JSON.stringify({ schema: 'aleph.test-policy.v1',
      services: { notes: { requireOwner: true } } });
    const trial = JSON.stringify({ schema: 'aleph.test-policy.v1',
      services: { notes: { requireOwner: false }, other: { keep: true } }, audit: ['fixture'] });
    const hash = createHash('sha256').update(backup).digest('hex');
    const plan = restorePlan(backup, trial, hash);
    const restored = JSON.parse(plan.next);
    let invalidRejected = false;
    try { restorePlan(backup, trial, '0'.repeat(64)); }
    catch (error) { invalidRejected = error.message === 'BACKUP_NOT_VERIFIED'; }
    ready = plan.preview.scope === 'services.notes' && restored.services.notes.requireOwner === true
      && restored.services.other.keep === true && restored.audit[0] === 'fixture' && invalidRejected;
    outcomes = { scope: plan.preview.scope, invalidRejected, preservedOtherService: restored.services.other.keep === true };
  }
  return { caseId, ready, requestId: randomUUID(), checkedAt: new Date().toISOString(),
    source, engine: 'ALEPH SDP 엔진', engineEnforced: 'not_run', outcomes };
}
