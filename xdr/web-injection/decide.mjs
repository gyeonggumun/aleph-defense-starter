// Standalone: raw Wazuh alerts and five-field reader summaries are supported.
const PATTERNS = [
  [/SQL.*(?:구문|표식|표기|주입)|데이터베이스 조회|sql injection|union\s+select/iu, 'repeated_sql_syntax'],
  [/스크립트.*(?:삽입|표식|주입)|script injection|cross.site scripting|<script\b/iu, 'repeated_script_injection'],
  [/경로.*(?:거슬러|이탈|탐색)|path traversal|(?:\.\.\/){2}/iu, 'repeated_path_traversal'],
  [/명령 구분자|command injection/iu, 'repeated_command_separator'],
];
const AMBIGUOUS = /따옴표|select|스크립트|경로.*up|SQL|이상한 검색|주입처럼|구분 문자|(?:요청 주소|URL|URI).*(?:평소보다\s*(?:길|깁)|비정상.*(?:길|깁))/iu;

async function askJev(summary) {
  const service = globalThis.Jev ?? globalThis.jev;
  const reviewer = service?.reviewWebInjectionAlert ?? service?.review;
  if (typeof reviewer !== 'function' || typeof setTimeout !== 'function') return null;
  let timeout;
  try {
    const result = await Promise.race([
      Promise.resolve().then(() => reviewer.call(service, summary)),
      new Promise(resolve => { timeout = setTimeout(() => resolve(null), 1500); }),
    ]);
    return Number.isFinite(result?.confidence) && result.confidence >= 0 && result.confidence <= 1
      ? result.confidence : null;
  } catch { return null; }
  finally { if (timeout) clearTimeout(timeout); }
}

export async function decide(alert = {}) {
  const description = String(alert?.rule?.description ?? alert?.description ?? '');
  const level = Number(alert?.rule?.level ?? alert?.ruleLevel ?? alert?.level ?? 0);
  const count = Number(alert?.data?.count ?? alert?.count
    ?? description.match(/(\d+)\s*(?:건|번|회|attempts|requests)/iu)?.[1] ?? 0);
  const source = String(alert?.data?.srcip ?? alert?.sourceAddress ?? alert?.sourceIp ?? alert?.srcip ?? '');
  if (!description) return { action: 'record', confidence: 0, reason: 'invalid_alert' };
  const match = PATTERNS.find(([expression]) => expression.test(description));
  const repeated = Boolean(source) && Number.isFinite(count) && count >= 8 && level >= 10;
  if (repeated && match) return { action: 'block', confidence: 0.9, reason: match[1] };
  if (match || (level > 3 && AMBIGUOUS.test(description))) {
    const reason = match?.[1] ?? 'ambiguous_web_input';
    // Send only derived signals; request payloads, accounts and descriptions stay local.
    const reviewed = await askJev({ pattern: reason, ruleLevel: level, count });
    // A model score alone cannot establish repeated, clear injection evidence.
    const confidence = reviewed === null ? 0.5 : Math.min(reviewed, 0.84);
    return { action: confidence >= 0.5 ? 'alert' : 'record', confidence, reason };
  }
  return { action: 'record', confidence: 0.05, reason: 'normal_web_request' };
}
