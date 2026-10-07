import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { extractAlert } from '../brute-force/read-alerts.mjs';
export { extractAlert } from '../brute-force/read-alerts.mjs';

export async function readAlerts(path = new URL('../fixtures/web-injection.json', import.meta.url)) {
  const fixture = JSON.parse(await readFile(path, 'utf8'));
  if (fixture?.schema !== 'aleph.xdr.fixture.v1' || fixture.moduleKey !== 'web-injection'
      || !Array.isArray(fixture.alerts)) throw new Error('웹 주입 경보 묶음 형식이 아닙니다.');
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
