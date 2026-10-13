import config from '../aleph.config.json' with { type: 'json' };
import { getLastCheckEvidence, runAttackChecks } from './attack-check.mjs';
import { runStage12RuleCheck } from './stage12-rule-checks.mjs';

const CACHE_MS = 60_000;
let cached;
let inFlight;

function responseJson(response, status, payload) {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  return response.status(status).json(payload);
}

function readFixture(settings) {
  if (typeof settings.STAGE12_CHECK_REPORT_JSON !== 'string') return null;
  try {
    const report = JSON.parse(settings.STAGE12_CHECK_REPORT_JSON);
    if (report?.schema !== 'aleph.stage12.checks.v1' || !Array.isArray(report.attempts)) return null;
    const total = report.attempts.length;
    const blocked = report.attempts.filter(item => item.result === 'blocked').length;
    const failed = report.attempts.filter(item => item.result === 'breached').length;
    const notRun = report.attempts.filter(item => item.result === 'not_run' || item.observed === 'not_run').length;
    return { ...report, total, blocked, failed, notRun, executed: total - notRun };
  } catch { return null; }
}

export async function getStage12CheckReport(settings = process.env) {
  const fixture = readFixture(settings);
  if (fixture) return fixture;
  if (cached && Date.now() - cached.at < CACHE_MS) return cached.report;
  if (inFlight) return inFlight;
  inFlight = collectStage12CheckReport(settings);
  try {
    const report = await inFlight;
    cached = { at: Date.now(), report };
    return report;
  } finally { inFlight = undefined; }
}

async function collectStage12CheckReport(settings) {
  const attempts = await runAttackChecks(config);
  const evidence = new Map(getLastCheckEvidence().map(item => [item.attackId, item]));
  const checkedAt = new Date().toISOString();
  const report = {
    schema: 'aleph.stage12.checks.v1', step: config.step,
    commit: /^[a-f0-9]{40}$/iu.test(settings.VERCEL_GIT_COMMIT_SHA ?? '')
      ? settings.VERCEL_GIT_COMMIT_SHA.toLowerCase() : null,
    checkedAt, target: config.publicAppUrl, total: attempts.length,
    blocked: attempts.filter(item => item.result === 'blocked').length,
    failed: attempts.filter(item => item.result === 'breached').length,
    notRun: attempts.filter(item => item.result === 'not_run').length,
    executed: attempts.filter(item => item.result !== 'not_run').length,
    attempts: attempts.map(item => ({ ...item,
      requestId: evidence.get(item.attackId)?.requestId ?? null,
      checkedAt: evidence.get(item.attackId)?.checkedAt ?? null,
    })),
  };
  return report;
}

export async function handleStage12ChecksRequest(request, response, settings = process.env) {
  if (request.method !== 'GET') {
    response.setHeader('Allow', 'GET');
    return responseJson(response, 405, { error: 'METHOD_NOT_ALLOWED' });
  }
  if (request.query?.case !== undefined) {
    try {
      const result = await runStage12RuleCheck(request.query.case);
      return result ? responseJson(response, 200, result)
        : responseJson(response, 400, { error: 'UNKNOWN_CHECK' });
    } catch {
      return responseJson(response, 503, { error: 'RULE_CHECK_UNAVAILABLE' });
    }
  }
  try {
    return responseJson(response, 200, await getStage12CheckReport(settings));
  } catch {
    return responseJson(response, 503, { error: 'CHECKS_UNAVAILABLE' });
  }
}
