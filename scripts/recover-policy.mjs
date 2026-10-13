import { createHash } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const digest = value => createHash('sha256').update(value).digest('hex');
const fail = message => { throw new Error(message); };

export function planPolicyRestore(backupText, trialText, trustedSha256) {
  if (!/^[a-f0-9]{64}$/iu.test(trustedSha256 ?? '')
      || digest(backupText) !== trustedSha256.toLowerCase()) fail('BACKUP_NOT_VERIFIED');
  let backup;
  let trial;
  try {
    backup = JSON.parse(backupText);
    trial = JSON.parse(trialText);
  } catch { fail('INVALID_POLICY_JSON'); }
  if (backup?.schema !== 'aleph.test-policy.v1' || trial?.schema !== backup.schema
      || !backup.services?.notes || !trial.services?.notes
      || typeof backup.services.notes !== 'object' || Array.isArray(backup.services.notes)
      || typeof trial.services.notes !== 'object' || Array.isArray(trial.services.notes)) {
    fail('INVALID_POLICY_SCOPE');
  }
  const before = trial.services.notes;
  const after = backup.services.notes;
  const next = { ...trial, services: { ...trial.services, notes: after } };
  return {
    preview: { backupSha256: trustedSha256.toLowerCase(), scope: 'services.notes',
      changed: JSON.stringify(before) !== JSON.stringify(after), before, after },
    next: `${JSON.stringify(next, null, 2)}\n`,
  };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const [mode, backupPath, trialPath, trustedSha256, confirmation] = process.argv.slice(2);
    if (!['preview', 'apply'].includes(mode) || !backupPath || !trialPath
        || !resolve(trialPath).endsWith('.trial.json')) fail('USAGE: preview|apply BACKUP TRIAL.trial.json TRUSTED_SHA256 [CONFIRM_SHA256]');
    const { preview, next } = planPolicyRestore(readFileSync(backupPath, 'utf8'),
      readFileSync(trialPath, 'utf8'), trustedSha256);
    process.stdout.write(`${JSON.stringify(preview, null, 2)}\n`);
    if (mode === 'apply') {
      if (confirmation !== preview.backupSha256) fail('CONFIRMATION_REQUIRED');
      writeFileSync(trialPath, next, { flag: 'w' });
      process.stdout.write('TEST_POLICY_RESTORED\n');
    }
  } catch (error) {
    process.stderr.write(`${error.message}\n`);
    process.exitCode = 1;
  }
}
