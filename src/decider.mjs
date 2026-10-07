// ALEPH SDP 엔진이 확인한 요청만 받는 학생 판정기 시작점입니다.
// 6단계부터 규칙을 하나씩 추가합니다. 이 기본 응답은 모든 요청을 거부합니다.
// 요청 본문의 userId, role, 기기 키, 토큰을 별도로 믿거나 저장하지 마세요.
import { activeDenyRuleFor } from '../xdr/brute-force/ztna-rules.mjs';
import { activeDenyRuleFor as webInjectionRuleFor } from '../xdr/web-injection/ztna-rules.mjs';

export const RULE_IDS = Object.freeze(['starter.deny', 'xdr.brute_force_source_ip', 'xdr.web_injection_source_ip']);

export async function decide(request) {
  const bruteForceRule = await activeDenyRuleFor(request?.signals?.source);
  const webInjectionRule = await webInjectionRuleFor(request?.signals?.source);
  return {
    schema: 'aleph.decision.v1',
    requestId: request.requestId,
    decision: 'deny',
    reasonCode: 'starter_not_ready',
    ruleIds: [RULE_IDS[0], ...(bruteForceRule ? [RULE_IDS[1]] : []), ...(webInjectionRule ? [RULE_IDS[2]] : [])],
  };
}
