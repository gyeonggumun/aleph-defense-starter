import { isIP } from 'node:net';
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';
import { extractAlert } from './read-alerts.mjs';

const defaultRoot = fileURLToPath(new URL('../../', import.meta.url));
const RULE_ID = 'xdr.known_cve_source_ip';
const SCHEMA = 'aleph.xdr.known-cve-deny.v1';
const ALERT_ID = /^[a-z0-9._-]{1,80}$/iu;
const TTL_MS = 24 * 60 * 60 * 1000;

function validRule(rule) {
  return rule?.ruleId === RULE_ID && typeof rule.sourceAddress === 'string' && isIP(rule.sourceAddress)
    && typeof rule.evidenceAlertId === 'string' && ALERT_ID.test(rule.evidenceAlertId) && rule.reason === 'log4shell_remote_lookup'
    && Number.isFinite(rule.confidence) && rule.confidence >= 0.85 && rule.confidence <= 1
    && Number.isFinite(Date.parse(rule.createdAt)) && Number.isFinite(Date.parse(rule.expiresAt));
}

async function readRules(root) {
  let content;
  try { content = await readFile(join(root, 'xdr', 'known-cve', 'deny-rules.json'), 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  const store = JSON.parse(content);
  if (store.schema !== SCHEMA || !Array.isArray(store.rules)) throw new Error('INVALID_KNOWN_CVE_RULE_STORE');
  return store.rules.filter(validRule);
}

export function findActiveDenyRule(sourceAddress, rules, now = Date.now()) {
  if (typeof sourceAddress !== 'string' || !isIP(sourceAddress) || !Array.isArray(rules)) return null;
  return rules.find(rule => validRule(rule) && rule.sourceAddress === sourceAddress
    && Date.parse(rule.createdAt) <= now && Date.parse(rule.expiresAt) > now) ?? null;
}

export async function activeDenyRuleFor(sourceAddress, now = Date.now()) {
  return findActiveDenyRule(sourceAddress, await readRules(defaultRoot), now);
}

export async function respond({ root = defaultRoot, alerts, decisions, now = Date.now() }) {
  const byId = new Map(alerts.map(alert => [alert?.id, alert]));
  const processedIds = new Set(alerts.map(alert => alert?.id));
  const retained = (await readRules(root)).filter(rule => !processedIds.has(rule.evidenceAlertId)
    && Date.parse(rule.expiresAt) > now);
  const rules = [];
  const entries = [];
  for (const decision of decisions) {
    const alert = byId.get(decision?.alertId);
    if (!alert || !ALERT_ID.test(decision.alertId ?? '')) continue;
    const confirmed = decide(alert);
    if (decision.action !== confirmed.action || decision.reason !== confirmed.reason
        || decision.confidence !== confirmed.confidence || confirmed.action === 'record') continue;
    const row = extractAlert(alert);
    if (confirmed.action === 'block' && isIP(row.sourceAddress)) {
      rules.push({ ruleId: RULE_ID, sourceAddress: row.sourceAddress, evidenceAlertId: decision.alertId,
        reason: confirmed.reason, confidence: confirmed.confidence,
        createdAt: new Date(now).toISOString(), expiresAt: new Date(now + TTL_MS).toISOString() });
    }
    entries.push(JSON.stringify({ moduleKey: 'known-cve', alertId: decision.alertId,
      timestamp: row.timestamp, processedAt: new Date(now).toISOString(),
      sourceAddress: row.sourceAddress, action: confirmed.action,
      confidence: confirmed.confidence, pattern: confirmed.reason }));
  }
  const directory = join(root, 'xdr', 'known-cve');
  await mkdir(directory, { recursive: true });
  const path = join(directory, 'deny-rules.json');
  await writeFile(`${path}.tmp`, `${JSON.stringify({ schema: SCHEMA, rules: [...retained, ...rules] }, null, 2)}\n`, 'utf8');
  await rename(`${path}.tmp`, path);
  if (entries.length) await appendFile(join(root, 'xdr', 'alerts.log'), `${entries.join('\n')}\n`, 'utf8');
  return [...retained, ...rules];
}
