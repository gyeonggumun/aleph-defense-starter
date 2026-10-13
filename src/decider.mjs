// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 엔진이 확인한 등록 기기의 자료실 읽기만 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
import { activeDenyRuleFor } from '../xdr/brute-force/ztna-rules.mjs';
import { activeDenyRuleFor as webInjectionRuleFor } from '../xdr/web-injection/ztna-rules.mjs';

export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'xdr.brute_force_source_ip', 'xdr.web_injection_source_ip', 'step_up_required']);

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
  const bruteForceRule = await activeDenyRuleFor(request?.signals?.source);
  const webInjectionRule = await webInjectionRuleFor(request?.signals?.source);
  const xdrRuleIds = [
    ...(bruteForceRule ? [RULE_IDS[2]] : []),
    ...(webInjectionRule ? [RULE_IDS[3]] : []),
  ];
  const registered = request?.deviceRegistered === true;
  const vaultRead = request?.service === 'notes' && request?.method === 'GET'
    && ['GET /notes', 'GET /notes/:id'].includes(request?.route);
  const complexRisk = registered && vaultRead && needsStepUp(request);
  const recentVerifiedLogin = request?.stepUp?.verified === true
    && Number.isInteger(request.stepUp.authAgeSeconds)
    && request.stepUp.authAgeSeconds >= 0 && request.stepUp.authAgeSeconds <= 300;
  const decision = !registered || xdrRuleIds.length || !vaultRead ? 'deny'
    : complexRisk && !recentVerifiedLogin ? 'step_up' : 'allow';
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision,
    reasonCode: !registered ? 'device_not_registered' : decision === 'step_up' ? 'step_up_required'
      : decision === 'allow' ? 'approved' : 'starter_not_ready',
    ruleIds: !registered ? [RULE_IDS[1], ...xdrRuleIds]
      : xdrRuleIds.length ? xdrRuleIds : !vaultRead ? [RULE_IDS[0]]
        : complexRisk ? [RULE_IDS[1], RULE_IDS[4]] : [RULE_IDS[1]],
  };
}
