const PATTERNS = [
  {
    name: 'untrusted_service_change',
    condition: '서명 없는 서비스 생성·실행 파일 변경, 또는 평소 목록에 없는 서비스의 임시 실행 파일·재시작 지속성이 함께 확인됩니다.',
    evidence: 'MITRE ATT&CK T1543은 지속 실행을 위한 시스템 서비스 생성·변경을 설명합니다. 임시 경로·서명 부재의 조합은 이 모듈의 보수적 격리 기준입니다. https://attack.mitre.org/techniques/T1543/',
  },
  {
    name: 'unfamiliar_scheduled_task',
    condition: '낯선·임의 이름의 예약 작업이 임시 실행 파일을 가리키거나 시작 프로그램과 같은 임시 파일을 함께 실행합니다.',
    evidence: 'MITRE ATT&CK T1053은 악성 코드의 반복 실행을 위한 예약 작업 악용을 설명합니다. https://attack.mitre.org/techniques/T1053/',
  },
  {
    name: 'unfamiliar_startup_entry',
    condition: '평소 목록에 없는 실행 파일이 시작 폴더에 추가됐거나 다른 자동 실행 경로와 같은 임시 파일을 가리킵니다.',
    evidence: 'MITRE ATT&CK T1547.001은 부팅·로그온 시 실행되는 시작 폴더 항목을 통한 지속성을 설명합니다. https://attack.mitre.org/techniques/T1547/001/',
  },
];

export function decide(alert = {}) {
  const data = alert?.data ?? {};
  const description = String(alert?.rule?.description ?? alert?.description ?? '').slice(0, 4096);
  const path = String(data.path ?? alert?.path ?? '').slice(0, 4096);
  const service = /서비스|\bservice\b/iu.test(description);
  const task = /예약\s*작업|scheduled\s*task/iu.test(description);
  const startup = /시작\s*(?:폴더|프로그램|항목)|startup/iu.test(description);
  const temporary = /[\\/]temp[\\/]|임시\s*(?:폴더|파일)|temporary/iu.test(`${path} ${description}`);
  const startupPath = /[\\/]startup[\\/]/iu.test(path);
  const unfamiliar = /평소\s*목록에\s*없|처음\s*보는|낯선|임의\s*문자열|unfamiliar|unknown|random/iu.test(description);
  // Missing signature information is not proof that the binary is unsigned.
  const unsigned = /서명(?:이|은)?\s*없|서명\s*없는|\bunsigned\b/iu.test(description) || data.signed === false;
  const changed = /새\s*서비스|등록|추가|바뀌|changed|created|registered|added/iu.test(description);
  const repeated = Number(data.count ?? 0) >= 3;
  const persistent = /다시\s*켜도|남도록|reboot|persist/iu.test(description);
  const explicitNormal = /로그인했습니다|로그아웃했습니다|자료실\s*화면|정의\s*업데이트.*끝|읽기만|기존.*서명된|평소.*그대로|기존\s*예약\s*작업.*마쳤/iu.test(description);

  let confidence = 0.05;
  let reason = 'no_pattern_match';
  if (service && ((unsigned && changed && (temporary || repeated))
      || (unfamiliar && changed && temporary && persistent))) {
    confidence = 0.97;
    reason = PATTERNS[0].name;
  } else if (task && temporary && (unfamiliar || startup)) {
    confidence = 0.96;
    reason = PATTERNS[1].name;
  } else if (startup && unfamiliar && changed && startupPath) {
    confidence = 0.95;
    reason = PATTERNS[2].name;
  } else if (!explicitNormal && (service || task || startup || temporary)) {
    confidence = 0.6;
    reason = service ? PATTERNS[0].name : task ? PATTERNS[1].name : PATTERNS[2].name;
  }
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason };
}
