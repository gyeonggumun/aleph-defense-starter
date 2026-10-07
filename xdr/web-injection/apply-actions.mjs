import { isIP } from 'node:net';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { extractAlert } from './read-alerts.mjs';

const RULE_ID = 'xdr.web_injection_source_ip';
const RULES_SCHEMA = 'aleph.xdr.web-injection-deny.v1';
const PATTERNS = new Set(['repeated_sql_syntax', 'repeated_script_injection', 'repeated_path_traversal', 'repeated_command_separator', 'ambiguous_web_input']);
const ALERT_ID = /^[a-z0-9._-]{1,80}$/iu;
const RULE_TTL_MS = 24 * 60 * 60 * 1000;

export async function applyActions({ root, alerts, decisions, now = Date.now() }) {
  const alertsById = new Map(alerts.map(alert => [alert?.id, alert]));
  const createdAt = new Date(now).toISOString();
  const expiresAt = new Date(now + RULE_TTL_MS).toISOString();
  const rules = decisions.flatMap(decision => {
    const alert = alertsById.get(decision?.alertId);
    const sourceAddress = alert ? extractAlert(alert).sourceAddress : '';
    if (decision?.action !== 'block' || !ALERT_ID.test(decision.alertId || '')
        || !isIP(sourceAddress) || !Number.isFinite(decision.confidence)
        || decision.confidence < 0.85 || !PATTERNS.has(decision.reason)) return [];
    return [{ ruleId: RULE_ID, sourceAddress, evidenceAlertId: decision.alertId,
      reason: decision.reason, confidence: decision.confidence, createdAt, expiresAt }];
  });

  const moduleDir = join(root, 'xdr', 'web-injection');
  await mkdir(moduleDir, { recursive: true });
  const rulesPath = join(moduleDir, 'deny-rules.json');
  await writeFile(rulesPath, `${JSON.stringify({ schema: RULES_SCHEMA, rules }, null, 2)}\n`, 'utf8');

  const logPath = join(root, 'xdr', 'alerts.log');
  let existing = '';
  try { existing = await readFile(logPath, 'utf8'); } catch {}
  let lines = existing.split(/\r?\n/u).filter(Boolean);
  for (const decision of decisions) {
    if (!['block', 'alert'].includes(decision?.action) || !ALERT_ID.test(decision.alertId || '')
        || !PATTERNS.has(decision.reason)) continue;
    const alert = alertsById.get(decision.alertId);
    if (!alert) continue;
    const normalized = extractAlert(alert);
    const entry = JSON.stringify({ alertId: decision.alertId, timestamp: normalized.timestamp,
      action: decision.action, sourceAddress: normalized.sourceAddress,
      pattern: decision.reason, confidence: decision.confidence });
    let replaced = false;
    lines = lines.flatMap(line => {
      try {
        if (JSON.parse(line)?.alertId !== decision.alertId) return [line];
        if (replaced) return [];
        replaced = true;
        return [entry];
      } catch { return [line]; }
    });
    if (!replaced) lines.push(entry);
  }
  await mkdir(dirname(logPath), { recursive: true });
  await writeFile(logPath, `${lines.length ? `${lines.join('\n')}\n` : ''}`, 'utf8');
  return rules;
}
