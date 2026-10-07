import { isIP } from 'node:net';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';

const fixturePath = fileURLToPath(new URL('../fixtures/brute-force.json', import.meta.url));
const sensitivePatterns = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/giu,
  /\b(?:password|passwd|pwd|secret|token|api[_ -]?key|authorization)\b\s*[:=]\s*["']?[^\s,"';]+/giu,
  /\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]{8,}={0,2}/giu,
  /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/gu,
  /\b(?:gh[pousr]_|github_pat_|glpat-|sb_secret_|sk_live_|sk_test_)[A-Za-z0-9_-]{8,}\b/giu,
];

function safeText(value, maxLength) {
  if (typeof value !== 'string') return '';
  return sensitivePatterns.reduce((text, pattern) => text.replace(pattern, '[REDACTED]'), value)
    .slice(0, maxLength);
}

export function extractAlert(alert) {
  const sourceAddress = alert?.data?.srcip ?? alert?.sourceAddress;
  const description = alert?.rule?.description ?? alert?.description;
  const account = alert?.data?.srcuser ?? alert?.account;
  const address = typeof sourceAddress === 'string' && isIP(sourceAddress) ? sourceAddress : '';
  const timestamp = typeof alert?.timestamp === 'string' && Number.isFinite(Date.parse(alert.timestamp))
    ? new Date(alert.timestamp).toISOString() : '';
  const level = Number(alert?.rule?.level ?? alert?.ruleLevel);
  return {
    timestamp,
    sourceAddress: address,
    account: safeText(account, 80),
    ruleLevel: Number.isInteger(level) && level >= 0 ? level : null,
    description: safeText(description, 300),
  };
}

export async function readAlerts(path = fixturePath) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'brute-force'
      || !Array.isArray(fixture.alerts)) {
    throw new Error('무차별 대입 경보 묶음 형식이 아닙니다.');
  }
  return fixture.alerts.map(extractAlert);
}

const isMain = process.argv[1] && fileURLToPath(import.meta.url) === process.argv[1];
if (isMain) {
  try {
    for (const alert of await readAlerts()) process.stdout.write(`${JSON.stringify(alert)}\n`);
  } catch {
    process.stderr.write('경보 묶음을 읽을 수 없습니다.\n');
    process.exitCode = 1;
  }
}
