import { isIP } from 'node:net';
import { createHash } from 'node:crypto';
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';
import { extractAlert } from './read-alerts.mjs';

const defaultRoot = fileURLToPath(new URL('../../', import.meta.url));
const RULE_ID = 'xdr.privilege_session';
const SCHEMA = 'aleph.xdr.privilege-deny.v1';
const ALERT_ID = /^[a-z0-9._-]{1,80}$/iu;
const PATTERN_NAMES = new Set(["unexpected_admin_membership","unexpected_privileged_command","unexpected_session_elevation"]);
const TTL_MS = 24 * 60 * 60 * 1000;
const SUBJECT_ID = /^[a-z0-9_:-]{1,160}$/iu;

// Only public practice aliases have this local mapping. Real subjects require
// a resolver supplied by the server after issuer/class/project verification.
export function fixtureSubjectFor(account) {
  if (typeof account !== 'string' || !/^(?:user\d{2}|admin\d{2}|svc-lab)$/u.test(account)) return null;
  return `xdr_fixture_${createHash('sha256').update(`privilege:${account}`).digest('hex')}`;
}

function validRule(rule) {
  return rule?.ruleId === RULE_ID && typeof rule.sourceAddress === 'string' && isIP(rule.sourceAddress)
    && typeof rule.subjectId === 'string' && SUBJECT_ID.test(rule.subjectId)
    && typeof rule.evidenceAlertId === 'string' && ALERT_ID.test(rule.evidenceAlertId) && PATTERN_NAMES.has(rule.reason)
    && Number.isFinite(rule.confidence) && rule.confidence >= 0.85 && rule.confidence <= 1
    && Number.isFinite(Date.parse(rule.createdAt)) && Number.isFinite(Date.parse(rule.expiresAt));
}

async function readRules(root) {
  let content;
  try { content = await readFile(join(root, 'xdr', 'privilege', 'deny-rules.json'), 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  const store = JSON.parse(content);
  if (store.schema !== SCHEMA || !Array.isArray(store.rules)) throw new Error('INVALID_PRIVILEGE_RULE_STORE');
  return store.rules.filter(validRule);
}

export function findActiveDenyRule(subjectId, sourceAddress, rules, now = Date.now()) {
  if (typeof subjectId !== 'string' || !SUBJECT_ID.test(subjectId)
      || typeof sourceAddress !== 'string' || !isIP(sourceAddress) || !Array.isArray(rules)) return null;
  return rules.find(rule => validRule(rule) && rule.subjectId === subjectId && rule.sourceAddress === sourceAddress
    && Date.parse(rule.createdAt) <= now && Date.parse(rule.expiresAt) > now) ?? null;
}

export async function activeDenyRuleFor(subjectId, sourceAddress, now = Date.now()) {
  return findActiveDenyRule(subjectId, sourceAddress, await readRules(defaultRoot), now);
}

export async function respond({ root = defaultRoot, alerts, decisions, now = Date.now(),
  subjectForAccount = fixtureSubjectFor }) {
  const byId = new Map(alerts.map(alert => [alert?.id, alert]));
  const retained = (await readRules(root)).filter(rule => Date.parse(rule.expiresAt) > now);
  const rules = [];
  const entries = [];
  for (const decision of decisions) {
    const alert = byId.get(decision?.alertId);
    if (!alert || !ALERT_ID.test(decision.alertId ?? '')) continue;
    const confirmed = decide(alert);
    if (decision.action !== confirmed.action || decision.reason !== confirmed.reason
        || decision.confidence !== confirmed.confidence || confirmed.action === 'record') continue;
    const row = extractAlert(alert);
    const resolved = await subjectForAccount(row.account);
    const subjectId = typeof resolved === 'string' && SUBJECT_ID.test(resolved) ? resolved : null;
    if (confirmed.action === 'block' && subjectId && isIP(row.sourceAddress)) {
      rules.push({ ruleId: RULE_ID, sourceAddress: row.sourceAddress, evidenceAlertId: decision.alertId,
        subjectId,
        reason: confirmed.reason, confidence: confirmed.confidence,
        createdAt: new Date(now).toISOString(), expiresAt: new Date(now + TTL_MS).toISOString() });
    }
    entries.push(JSON.stringify({ moduleKey: 'privilege', alertId: decision.alertId,
      timestamp: row.timestamp, processedAt: new Date(now).toISOString(),
      sourceAddress: row.sourceAddress, action: confirmed.action,
      subjectId, enforcement: confirmed.action === 'block' && subjectId && isIP(row.sourceAddress) ? 'local_deny_rule' : 'not_run',
      confidence: confirmed.confidence, pattern: confirmed.reason }));
  }
  const directory = join(root, 'xdr', 'privilege');
  await mkdir(directory, { recursive: true });
  const path = join(directory, 'deny-rules.json');
  const merged = [...retained.filter(old => !rules.some(rule => rule.evidenceAlertId === old.evidenceAlertId
    && rule.subjectId === old.subjectId && rule.sourceAddress === old.sourceAddress)), ...rules];
  await writeFile(`${path}.tmp`, `${JSON.stringify({ schema: SCHEMA, rules: merged }, null, 2)}\n`, 'utf8');
  await rename(`${path}.tmp`, path);
  if (entries.length) await appendFile(join(root, 'xdr', 'alerts.log'), `${entries.join('\n')}\n`, 'utf8');
  return merged;
}
