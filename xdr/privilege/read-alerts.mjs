import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { extractAlert as extractBase } from '../brute-force/read-alerts.mjs';

function redact(value) {
  return value.replace(/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*/giu, '[REDACTED]')
    .replace(/\b(?:client[_-]?secret|access[_-]?token|session[_-]?token)\s*[:=]\s*["']?[^\s,"';]+/giu, '[REDACTED]')
    .replace(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/giu, '[REDACTED]');
}

export function extractAlert(alert) {
  const row = extractBase(alert);
  return { ...row, account: redact(row.account), description: redact(row.description) };
}

export async function readAlerts(path = new URL('../fixtures/privilege.json', import.meta.url)) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'privilege'
      || !Array.isArray(fixture.alerts)) throw new Error('권한 변경 경보 묶음 형식이 아닙니다.');
  return fixture.alerts.map(extractAlert);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  try {
    for (const row of await readAlerts()) process.stdout.write(`${JSON.stringify(row)}\n`);
  } catch {
    process.stderr.write('경보 묶음을 읽을 수 없습니다.\n');
    process.exitCode = 1;
  }
}
