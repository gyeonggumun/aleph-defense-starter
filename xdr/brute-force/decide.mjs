import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { extractAlert } from './read-alerts.mjs';
import { addTemporaryDenyRule, logNonRecordOutcome } from './ztna-rules.mjs';

const patternsFile = fileURLToPath(new URL('./patterns.json', import.meta.url));
const { patterns } = JSON.parse(await readFile(patternsFile, 'utf8'));
const byName = new Map(patterns.map(pattern => [pattern.name, pattern]));

function failureCount(description) {
  const match = description.match(/(?:로그인\s*)?실패\D{0,16}(\d+)\s*건/u)
    ?? description.match(/실패\s*(\d+)\s*건/u);
  return match ? Number(match[1]) : 0;
}

function timeWindowSeconds(description) {
  const match = description.match(/(\d+)\s*분/u);
  return match ? Number(match[1]) * 60 : null;
}

function accountCount(alert, description) {
  const listed = typeof alert?.data?.accounts === 'string'
    ? alert.data.accounts.split(',').map(value => value.trim()).filter(Boolean).length : 0;
  const stated = description.match(/(?:서로\s*다른\s*)?계정\s*(\d+)\s*개/u);
  return Math.max(listed, stated ? Number(stated[1]) : 0,
    /여러\s*계정/u.test(description) ? 2 : 0);
}

function matchesSpray(alert, description) {
  return /같은\s*비밀번호/u.test(description) && accountCount(alert, description) >= 2;
}

function selectPattern(alert, normalized) {
  const description = normalized.description;
  if (matchesSpray(alert, description)
      || accountCount(alert, description) >= 2) return byName.get('password_spraying_across_accounts');
  const hasFailure = failureCount(description) >= 3 || alert?.rule?.mitre?.includes('T1110');
  return hasFailure ? byName.get('rapid_same_source_failures') : null;
}

function isClearAttack(alert, normalized, pattern) {
  if (!normalized.sourceAddress || !pattern) return false;
  if (pattern.name === 'password_spraying_across_accounts') {
    return matchesSpray(alert, normalized.description) && accountCount(alert, normalized.description) >= 5;
  }
  const count = failureCount(normalized.description);
  const windowSeconds = timeWindowSeconds(normalized.description);
  return count >= 30 && windowSeconds !== null && windowSeconds <= 180;
}

async function askJev(normalized, pattern) {
  const service = globalThis.Jev ?? globalThis.jev;
  const reviewer = service?.reviewBruteForceAlert ?? service?.review;
  if (typeof reviewer !== 'function') return null;
  let timeout;
  try {
    const response = await Promise.race([
      Promise.resolve().then(() => reviewer.call(service, {
        alert: normalized,
        pattern: { name: pattern.name, condition: pattern.condition, evidence: pattern.evidence },
      })),
      new Promise(resolve => { timeout = setTimeout(() => resolve(null), 1500); }),
    ]);
    return Number.isFinite(response?.confidence) && response.confidence >= 0 && response.confidence <= 1
      ? response.confidence : null;
  } catch {
    return null;
  } finally {
    clearTimeout(timeout);
  }
}

function actionForConfidence(confidence) {
  if (confidence >= 0.85) return 'block';
  if (confidence >= 0.5) return 'alert';
  return 'record';
}

export async function decide(alert) {
  const normalized = extractAlert(alert);
  const pattern = selectPattern(alert, normalized);
  let result;
  if (!pattern) {
    result = { action: 'record', confidence: 1, reason: 'no_matching_brute_force_pattern' };
  } else if (isClearAttack(alert, normalized, pattern)) {
    result = { action: 'block', confidence: 0.96, reason: pattern.name };
  } else {
    const confidence = await askJev(normalized, pattern);
    result = confidence === null
      ? { action: 'alert', confidence: 0.65, reason: pattern.name }
      : { action: actionForConfidence(confidence), confidence, reason: pattern.name };
  }

  if (result.action === 'block') {
    await addTemporaryDenyRule({ alertId: alert?.id, sourceAddress: normalized.sourceAddress,
      confidence: result.confidence, patternName: result.reason });
  }
  if (result.action !== 'record') {
    await logNonRecordOutcome({ alertId: alert?.id, normalized, action: result.action,
      confidence: result.confidence, patternName: result.reason });
  }
  return result;
}
