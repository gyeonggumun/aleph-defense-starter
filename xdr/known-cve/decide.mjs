const PATTERNS = [
  {
    name: 'log4shell_remote_lookup',
    condition: '요청 머리글·주소 인자에 원격 프로토콜과 목적지를 포함하고 닫힌 JNDI 조회 식이 있습니다.',
    evidence: 'Apache의 CVE-2021-44228 설명은 공격자가 제어한 로그·인자의 JNDI/LDAP 조회 악용을 설명합니다. https://logging.apache.org/security.html',
  },
  {
    name: 'known_cve_probe_context',
    condition: '취약점·JNDI·라이브러리 이름, 점검 도구 흔적 또는 불완전한 조회 식만 있어 완전한 악용 형태를 확인하지 못했습니다. 차단하지 않고 알립니다.',
    evidence: 'MITRE ATT&CK T1190은 외부 공개 앱의 취약점 악용과 CVE-2021-44228 사례를 다룹니다. 단어·도구 이름만으로 악용을 확정하지 않는 조건은 이 모듈의 보수적 판단 기준입니다. https://attack.mitre.org/techniques/T1190/',
  },
];

const REMOTE_LOOKUP = /\$\{\s*jndi\s*:\s*(?:ldap|ldaps|rmi|dns|iiop):\/\/[^\s{}]+\}/iu;
const PROBE_HINT = /CVE[-_ ]?2021[-_ ]?44228|log4(?:j|shell)|jndi|nuclei|취약점|점검\s*도구|라이브러리|중괄호|조회.*(?:잘린|불완전)/iu;

function requestText(alert) {
  const data = alert?.data ?? {};
  const pieces = [];
  let remaining = 32768;
  function collect(value, depth = 0) {
    if (remaining <= 0) return;
    if (typeof value === 'string') {
      const part = value.slice(0, Math.min(8192, remaining));
      pieces.push(part);
      remaining -= part.length + 1;
    }
    else if (value && typeof value === 'object' && depth < 3) {
      for (const child of Object.values(value).slice(0, 32)) collect(child, depth + 1);
    }
  }
  for (const value of [data.url, data.useragent, data.headers, data.args, data.parameters,
    data.query, data.body, alert?.request?.url, alert?.request?.headers, alert?.request?.args,
    alert?.url, alert?.useragent]) collect(value);
  return pieces.join(' ').slice(0, 32768);
}

export function decide(alert = {}) {
  let request = requestText(alert);
  // Decode only in memory; never evaluate lookup strings or contact their destinations.
  for (let i = 0; i < 2; i++) {
    try {
      const decoded = decodeURIComponent(request);
      if (decoded === request) break;
      request = decoded;
    } catch { break; }
  }
  const description = String(alert?.rule?.description ?? alert?.description ?? '').slice(0, 4096);
  let confidence = 0.05;
  let reason = 'no_pattern_match';
  if (REMOTE_LOOKUP.test(request)) {
    confidence = 0.98;
    reason = PATTERNS[0].name;
  } else if (PROBE_HINT.test(`${request} ${description}`)) {
    confidence = /jndi|nuclei|중괄호|잘린/iu.test(`${request} ${description}`) ? 0.65 : 0.55;
    reason = PATTERNS[1].name;
  }
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason };
}
