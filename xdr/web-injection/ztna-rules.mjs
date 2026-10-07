import { isIP } from 'node:net';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const rulesPath = fileURLToPath(new URL('./deny-rules.json', import.meta.url));
const RULE_ID = 'xdr.web_injection_source_ip';
const ALERT_ID = /^[a-z0-9._-]{1,80}$/iu;
const RULES_SCHEMA = 'aleph.xdr.web-injection-deny.v1';

async function readStore() {
  let content;
  try {
    content = await readFile(rulesPath, 'utf8');
  } catch (error) {
    if (error?.code === 'ENOENT') return { schema: RULES_SCHEMA, rules: [] };
    throw error;
  }
  const store = JSON.parse(content);
  if (store?.schema !== RULES_SCHEMA || !Array.isArray(store.rules)) {
    throw new Error('XDR 임시 차단 규칙 파일 형식이 아닙니다.');
  }
  return {
    schema: RULES_SCHEMA,
    rules: store.rules.filter(rule => rule?.ruleId === RULE_ID && isIP(rule.sourceAddress)
      && typeof rule.evidenceAlertId === 'string' && ALERT_ID.test(rule.evidenceAlertId)
      && Number.isFinite(Date.parse(rule.expiresAt))),
  };
}


export function findActiveDenyRule(sourceAddress, rules, now = Date.now()) {
  if (typeof sourceAddress !== 'string' || !isIP(sourceAddress) || !Array.isArray(rules)) return null;
  return rules.find(rule => rule?.ruleId === RULE_ID && rule.sourceAddress === sourceAddress
    && isIP(rule.sourceAddress) && Date.parse(rule.expiresAt) > now) ?? null;
}

export async function activeDenyRuleFor(sourceAddress, now = Date.now()) {
  const store = await readStore();
  return findActiveDenyRule(sourceAddress, store.rules, now);
}

