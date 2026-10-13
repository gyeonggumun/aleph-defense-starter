const PATTERNS = [
  {
    name: 'unexpected_admin_membership',
    condition: '관리자 그룹 추가가 낯선 원격 접속·여러 계정·즉시 명령 사용과 겹치거나 회수 직후 다시 관리자 권한을 얻습니다.',
    evidence: 'MITRE ATT&CK T1078은 도용된 정상 계정의 권한 사용을, T1098은 그룹 등 계정 권한 변경을 설명합니다. 복합 신호는 이 모듈의 보수적 차단 기준입니다. https://attack.mitre.org/techniques/T1078/ https://attack.mitre.org/techniques/T1098/',
  },
  {
    name: 'unexpected_privileged_command',
    condition: '관리자 명령 사용이 방금 얻은 권한·낯선 주소와 업무 시간 밖 접속·다른 계정 권한 사용 중 하나와 함께 확인됩니다.',
    evidence: 'MITRE ATT&CK T1078은 정상 계정 도용으로 높은 권한을 사용하는 공격을 설명합니다. 업무 시간 하나만으로 차단하지 않습니다. https://attack.mitre.org/techniques/T1078/',
  },
  {
    name: 'unexpected_session_elevation',
    condition: '세션이 관리자 권한으로 실제 변경되고 처음 보는 접속 주소가 함께 나타납니다. 취소·실패·계정 종류 조회 등 불명확한 권한 경보는 알림만 남깁니다.',
    evidence: 'MITRE ATT&CK T1068은 취약점 악용을 통한 권한 상승을 설명합니다. 이 경보만으로 취약점 악용은 확정하지 않으며 권한 변경과 낯선 접속의 조합을 탐지합니다. https://attack.mitre.org/techniques/T1068/',
  },
];

export function decide(alert = {}) {
  const description = String(alert?.rule?.description ?? alert?.description ?? '').slice(0, 4096);
  const data = alert?.data ?? {};
  const adminGroup = /관리자\s*그룹/iu.test(description) || /^(?:administrators|sudo|wheel)$/iu.test(String(data.group ?? ''));
  const membership = /추가|들어가|들어왔|add(?:ed)?|join/iu.test(description);
  const adminCommand = /관리자\s*명령|권한\s*명령|admin(?:istrator)?\s*command/iu.test(description);
  const commandRan = /실행|command\s*(?:ran|executed)/iu.test(description);
  const newlyElevated = /방금\s*관리자|곧바로|just.*(?:admin|elevat)/iu.test(description);
  const remote = /원격\s*주소|remote/iu.test(description);
  const unfamiliar = /처음\s*보는|처음\s*봅니다|낯선|unfamiliar|new\s*address/iu.test(description);
  const outsideHours = /시간\s*밖|업무처럼\s*보이지\s*않는\s*시각|outside.*hours/iu.test(description);
  const otherAccount = /다른\s*계정의\s*권한|another\s*account/iu.test(description);
  const restored = /빠진.*다시\s*관리자|removed.*(?:readded|added\s*again)/iu.test(description);
  const multipleAccounts = Number(data.count ?? 0) >= 3 && /계정/iu.test(description);
  const sessionElevated = /세션.*관리자\s*권한.*바뀌|session.*(?:elevat|admin)/iu.test(description);
  const incomplete = /취소|실패|관리자\s*그룹은\s*아닙|변경은\s*없|명령은\s*없|cancel|failed|not\s*admin/iu.test(description);
  const normal = /로그인했습니다|로그아웃했습니다|읽기만|자기\s*세션\s*정보.*조회|자료실.*열|평소\s*예약\s*작업.*확인|비밀번호.*변경/iu.test(description);
  let confidence = 0.05;
  let reason = 'no_pattern_match';
  if (!incomplete && adminGroup && (restored || (membership
      && (remote || multipleAccounts || (commandRan && (newlyElevated || outsideHours)))))) {
    confidence = 0.97;
    reason = PATTERNS[0].name;
  } else if (!incomplete && adminCommand && commandRan
      && (newlyElevated || (unfamiliar && outsideHours) || otherAccount)) {
    confidence = 0.96;
    reason = PATTERNS[1].name;
  } else if (!incomplete && sessionElevated && unfamiliar) {
    confidence = 0.95;
    reason = PATTERNS[2].name;
  } else if (!normal && /관리자|권한|그룹|계정\s*종류|administrator|privilege|group/iu.test(description)) {
    confidence = 0.6;
    reason = adminCommand ? PATTERNS[1].name : adminGroup || /그룹|group/iu.test(description) ? PATTERNS[0].name : PATTERNS[2].name;
  }
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason };
}
