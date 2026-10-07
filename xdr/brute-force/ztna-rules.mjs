import { isIP } from 'node:net';
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const rulesPath = fileURLToPath(new URL('./deny-rules.json', import.meta.url));
const alertLogPath = fileURLToPath(new URL('../alerts.log', import.meta.url));
const RULE_ID = 'xdr.brute_force_source_ip';
const PATTERNS = new Set(['rapid_same_source_failures', 'password_spraying_across_accounts']);
const ALERT_ID = /^[a-z0-9._-]{1,80}$/iu;
const RULES_SCHEMA = 'aleph.xdr.brute-force-deny.v1';
const TTL_MS = 15 * 60 * 1000;

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

async function saveStore(store) {
  await mkdir(dirname(rulesPath), { recursive: true });
  const tempPath = `${rulesPath}.tmp`;
  await writeFile(tempPath, `${JSON.stringify(store, null, 2)}\n`, 'utf8');
  await rename(tempPath, rulesPath);
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

export async function addTemporaryDenyRule({ alertId, sourceAddress, confidence, patternName }, now = Date.now()) {
  if (!ALERT_ID.test(alertId || '') || !isIP(sourceAddress) || !Number.isFinite(confidence) || confidence < 0.85
      || !PATTERNS.has(patternName)) return null;
  const store = await readStore();
  const rules = store.rules.filter(rule => rule.evidenceAlertId !== alertId && Date.parse(rule.expiresAt) > now);
  const rule = {
    ruleId: RULE_ID,
    sourceAddress,
    evidenceAlertId: alertId,
    reason: patternName,
    confidence,
    createdAt: new Date(now).toISOString(),
    expiresAt: new Date(now + TTL_MS).toISOString(),
  };
  await saveStore({ schema: RULES_SCHEMA, rules: [...rules, rule] });
  return rule;
}

export async function logNonRecordOutcome({ alertId, normalized, action, confidence, patternName }) {
  if (!ALERT_ID.test(alertId || '') || !['block', 'alert'].includes(action)
      || !PATTERNS.has(patternName)) return;
  let existing = '';
  try { existing = await readFile(alertLogPath, 'utf8'); } catch {}
  const entry = JSON.stringify({
    alertId,
    timestamp: normalized.timestamp,
    action,
    sourceAddress: normalized.sourceAddress,
    pattern: patternName,
    confidence,
  });
  let replaced = false;
  const lines = existing.split(/\r?\n/u).filter(Boolean).flatMap(line => {
    try {
      if (JSON.parse(line)?.alertId !== alertId) return [line];
      if (replaced) return [];
      replaced = true;
      return [entry];
    } catch { return [line]; }
  });
  if (replaced) await writeFile(alertLogPath, `${lines.join('\n')}\n`, 'utf8');
  else await appendFile(alertLogPath, `${entry}\n`, 'utf8');
}
