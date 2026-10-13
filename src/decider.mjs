// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 엔진이 확인한 등록 기기의 자료실 읽기만 허용합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
import { activeDenyRuleFor } from '../xdr/brute-force/ztna-rules.mjs';
import { activeDenyRuleFor as webInjectionRuleFor } from '../xdr/web-injection/ztna-rules.mjs';

export const RULE_IDS = Object.freeze(['starter.deny', 'device_registered', 'xdr.brute_force_source_ip', 'xdr.web_injection_source_ip']);

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
  const decision = !registered || xdrRuleIds.length || !vaultRead ? 'deny' : 'allow';
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision,
    reasonCode: !registered ? 'device_not_registered' : decision === 'allow' ? 'approved' : 'starter_not_ready',
    ruleIds: !registered ? [RULE_IDS[1], ...xdrRuleIds]
      : xdrRuleIds.length ? xdrRuleIds : vaultRead ? [RULE_IDS[1]] : [RULE_IDS[0]],
  };
}
