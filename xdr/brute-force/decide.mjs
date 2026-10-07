// Standalone decision module: no filesystem or relative module imports.
// The judge loads this file in an isolated context.
const FAILURE = /실패|failed|failure|brute.?force|password guessing/iu;
const PATTERNS = {
  rapid: {
    name: 'rapid_same_source_failures',
    condition: '같은 출발 주소에서 짧은 시간 동안 로그인 실패가 반복됩니다.',
    evidence: 'MITRE ATT&CK T1110은 반복적인 비밀번호 추측과 과도한 인증 실패를 다룹니다.',
  },
  spray: {
    name: 'password_spraying_across_accounts',
    condition: '같은 출발 주소가 같은 비밀번호를 여러 계정에 시도합니다.',
    evidence: 'MITRE ATT&CK T1110에는 여러 계정 대상 Password Spraying이 포함됩니다.',
  },
};

function normalizeAlert(alert = {}) {
  const description = String(alert.rule?.description ?? alert.description ?? '');
  const rawCount = alert.data?.count ?? alert.count;
  const describedCount = description.match(/(\d+)\s*(?:건|번|회|failures|attempts)/iu)?.[1];
  const count = Number(rawCount ?? describedCount ?? 0);
  const level = Number(alert.rule?.level ?? alert.ruleLevel ?? alert.level ?? 0);
  const accounts = alert.data?.accounts ?? alert.accounts;
  const accountCount = Array.isArray(accounts)
    ? new Set(accounts).size
    : typeof accounts === 'string'
      ? new Set(accounts.split(',').map(value => value.trim()).filter(Boolean)).size
      : 0;
  return {
    id: String(alert.id ?? alert.alertId ?? ''),
    description,
    level: Number.isFinite(level) ? level : 0,
    count: Number.isFinite(count) && count >= 0 ? count : 0,
    sourceAddress: String(alert.data?.srcip ?? alert.sourceAddress ?? alert.sourceIp ?? alert.srcip ?? ''),
    accountCount,
  };
}

function validConfidence(value) {
  return Number.isFinite(value) && value >= 0 && value <= 1;
}

async function askJev(item, pattern) {
  const service = globalThis.Jev ?? globalThis.jev;
  const reviewer = service?.reviewBruteForceAlert ?? service?.review;
  if (typeof reviewer === 'function') {
    if (typeof setTimeout !== 'function') return null;
    let timeout;
    try {
      const request = Promise.resolve().then(() => reviewer.call(service, { alert: item, pattern }));
      const response = await Promise.race([request, new Promise(resolve => {
        timeout = setTimeout(() => resolve(null), 1500);
      })]);
      return validConfidence(response?.confidence) ? response.confidence : null;
    } catch {
      return null;
    } finally {
      if (timeout) clearTimeout(timeout);
    }
  }

  const endpoint = typeof process !== 'undefined' ? process.env?.JEV_DECISION_URL : undefined;
  if (!endpoint || typeof fetch !== 'function') return null;
  try {
    const response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ alertId: item.id, sourceAddress: item.sourceAddress,
        ruleLevel: item.level, failureCount: item.count, pattern: pattern.name }),
      ...(typeof AbortSignal !== 'undefined' && typeof AbortSignal.timeout === 'function'
        ? { signal: AbortSignal.timeout(3000) } : {}),
    });
    const verdict = await response.json();
    return validConfidence(verdict?.confidence) ? verdict.confidence : null;
  } catch {
    return null;
  }
}

function actionForConfidence(confidence) {
  if (confidence >= 0.85) return 'block';
  if (confidence >= 0.5) return 'alert';
  return 'record';
}

export async function decide(alert) {
  const item = normalizeAlert(alert);
  if (!item.description) return { action: 'record', confidence: 0, reason: 'invalid_alert' };
  if (item.level <= 3 && item.count <= 1) {
    return { action: 'record', confidence: 0.05, reason: 'normal_login_event' };
  }

  const rapid = Boolean(item.sourceAddress) && item.level >= 10 && item.count >= 20
    && FAILURE.test(item.description);
  const spray = /같은 비밀번호|same password|password spray/iu.test(item.description);
  const manyAccounts = Boolean(item.sourceAddress) && item.level >= 10 && spray
    && (item.accountCount >= 5 || /여러\s*계정|계정\s*\d+개|multiple accounts/iu.test(item.description));
  if (rapid || manyAccounts) {
    const pattern = rapid ? PATTERNS.rapid : PATTERNS.spray;
    return { action: 'block', confidence: 0.9, reason: pattern.name };
  }

  if (FAILURE.test(item.description)) {
    const pattern = spray ? PATTERNS.spray : PATTERNS.rapid;
    const confidence = await askJev(item, pattern);
    if (confidence === null) {
      return { action: 'alert', confidence: 0.5, reason: pattern.name };
    }
    return { action: actionForConfidence(confidence), confidence, reason: pattern.name };
  }
  return { action: 'record', confidence: 0.1, reason: 'normal_login_event' };
}
