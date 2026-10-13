import { isIP } from 'node:net';
import { appendFile, mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decide } from './decide.mjs';
import { extractAlert } from './read-alerts.mjs';
import { decide as baseDecide } from '../../src/decider.mjs';

const defaultRoot = fileURLToPath(new URL('../../', import.meta.url));
const RULE_ID = 'xdr.exfiltration_destination';
const SCHEMA = 'aleph.xdr.exfiltration-deny.v1';
const ALERT_ID = /^[a-z0-9._-]{1,80}$/iu;
const PATTERN_NAMES = new Set(["large_unfamiliar_transfer","repeated_bulk_channel","off_hours_archive_transfer"]);
const TTL_MS = 24 * 60 * 60 * 1000;

function validRule(rule) {
  return rule?.ruleId === RULE_ID && typeof rule.destinationAddress === 'string' && isIP(rule.destinationAddress)
    && typeof rule.evidenceAlertId === 'string' && ALERT_ID.test(rule.evidenceAlertId) && PATTERN_NAMES.has(rule.reason)
    && Number.isFinite(rule.confidence) && rule.confidence >= 0.85 && rule.confidence <= 1
    && Number.isFinite(Date.parse(rule.createdAt)) && Number.isFinite(Date.parse(rule.expiresAt));
}

async function readRules(root) {
  let content;
  try { content = await readFile(join(root, 'xdr', 'exfiltration', 'deny-rules.json'), 'utf8'); }
  catch (error) { if (error.code === 'ENOENT') return []; throw error; }
  const store = JSON.parse(content);
  if (store.schema !== SCHEMA || !Array.isArray(store.rules)) throw new Error('INVALID_EXFILTRATION_RULE_STORE');
  return store.rules.filter(validRule);
}

export function findActiveDenyRule(destinationAddress, rules, now = Date.now()) {
  if (typeof destinationAddress !== 'string' || !isIP(destinationAddress) || !Array.isArray(rules)) return null;
  return rules.find(rule => validRule(rule) && rule.destinationAddress === destinationAddress
    && Date.parse(rule.createdAt) <= now && Date.parse(rule.expiresAt) > now) ?? null;
}

export async function activeDenyRuleFor(destinationAddress, now = Date.now()) {
  return findActiveDenyRule(destinationAddress, await readRules(defaultRoot), now);
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
    const destinationAddress = typeof alert?.data?.dstip === 'string' && isIP(alert.data.dstip) ? alert.data.dstip : null;
    if (confirmed.action === 'block' && destinationAddress) {
      rules.push({ ruleId: RULE_ID, destinationAddress, evidenceAlertId: decision.alertId,
        reason: confirmed.reason, confidence: confirmed.confidence,
        createdAt: new Date(now).toISOString(), expiresAt: new Date(now + TTL_MS).toISOString() });
    }
    entries.push(JSON.stringify({ moduleKey: 'exfiltration', alertId: decision.alertId,
      timestamp: row.timestamp, processedAt: new Date(now).toISOString(),
      sourceAddress: row.sourceAddress, destinationAddress, action: confirmed.action,
      enforcement: confirmed.action === 'block' && destinationAddress ? 'local_destination_deny' : 'not_run',
      confidence: confirmed.confidence, pattern: confirmed.reason }));
  }
  const directory = join(root, 'xdr', 'exfiltration');
  await mkdir(directory, { recursive: true });
  const path = join(directory, 'deny-rules.json');
  await writeFile(`${path}.tmp`, `${JSON.stringify({ schema: SCHEMA, rules: [...retained, ...rules] }, null, 2)}\n`, 'utf8');
  await rename(`${path}.tmp`, path);
  if (entries.length) await appendFile(join(root, 'xdr', 'alerts.log'), `${entries.join('\n')}\n`, 'utf8');
  return [...retained, ...rules];
}

// The outbound server supplies the resolved destination; never trust a browser header.
// No destination field is added to the ALEPH decision request contract.
export async function decideTransfer({ request, destinationAddress, root = defaultRoot, now = Date.now() }) {
  const base = await baseDecide(request);
  if (base.decision !== 'allow') return base;
  const validDestination = typeof destinationAddress === 'string' && Boolean(isIP(destinationAddress));
  const blocked = validDestination && findActiveDenyRule(destinationAddress, await readRules(root), now);
  if (!validDestination || blocked) return { ...base, decision: 'deny', reasonCode: 'starter_not_ready',
    ruleIds: [...new Set([...base.ruleIds, RULE_ID])] };
  return base;
}
