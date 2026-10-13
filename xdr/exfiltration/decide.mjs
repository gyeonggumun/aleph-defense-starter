const PATTERNS = [
  {
    name: 'large_unfamiliar_transfer',
    condition: '처음 보는 외부 목적지로 50MB 이상이 전송되거나 자료실 전체·다수 파일의 대량 외부 복사가 확인됩니다.',
    evidence: 'MITRE ATT&CK T1041·T1048은 명령 통로 또는 다른 프로토콜을 통한 자료 유출을 설명합니다. 50MB와 낯선 목적지의 조합은 이 모듈의 학습용 기준이며 통로 종류를 임의 확정하지 않습니다. https://attack.mitre.org/techniques/T1041/ https://attack.mitre.org/techniques/T1048/',
  },
  {
    name: 'repeated_bulk_channel',
    condition: '50MB 이상 전송이 5회 이상 반복되거나 낯선 포트로 다수 파일이 연속 전송됩니다.',
    evidence: 'MITRE ATT&CK T1041은 기존 명령 통로로, T1048은 다른 프로토콜로 자료가 나가는 행위를 설명합니다. 반복·용량·낯선 통로가 겹칠 때만 차단 후보로 둡니다. https://attack.mitre.org/techniques/T1041/ https://attack.mitre.org/techniques/T1048/',
  },
  {
    name: 'off_hours_archive_transfer',
    condition: '업무 시간 밖 압축 파일 전송 또는 낯선 목적지로 여러 압축 파일 전송이 50MB 이상 용량과 함께 확인됩니다.',
    evidence: 'MITRE ATT&CK T1048은 명령 통로 외 프로토콜을 통한 유출을 설명합니다. 압축·시각 단독 신호는 증명이 아니며 실제 외부 전송과 용량을 함께 검사합니다. https://attack.mitre.org/techniques/T1048/',
  },
];

const LARGE_BYTES = 50_000_000;

export function decide(alert = {}) {
  const data = alert?.data ?? {};
  const description = String(alert?.rule?.description ?? alert?.description ?? '').slice(0, 4096);
  const number = value => { const n = Number(value); return Number.isFinite(n) && n >= 0 ? n : 0; };
  const bytes = number(data.bytes);
  const files = number(data.files);
  const count = number(data.count);
  const destination = typeof data.dstip === 'string' && Boolean(data.dstip.trim());
  const unfamiliar = /처음\s*(?:보는|봅니다)|평소와\s*다른|낯선|unfamiliar|new\s*destination/iu.test(description);
  const unusualPort = /쓰지\s*않던\s*포트|낯선\s*포트|unusual\s*port/iu.test(description);
  const outsideHours = /시간\s*밖|outside.*hours/iu.test(description);
  const archive = /압축\s*파일|archive|\.zip\b/iu.test(description);
  const fullCopy = /자료실\s*전체.*외부|entire.*external/iu.test(description);
  const noTransfer = /전송.*(?:없|실패|취소)|큰\s*파일은\s*아닙|failed|cancelled/iu.test(description);
  const normal = /내\s*메모.*(?:읽|저장)|공지를\s*읽|작은\s*동기화.*끝|검색\s*결과.*받|화면\s*새로고침|첨부\s*그림.*열|세션\s*확인|로그아웃/iu.test(description);
  let confidence = 0.05;
  let reason = 'no_pattern_match';
  if (!noTransfer && destination && bytes >= LARGE_BYTES) {
    if (archive && ((outsideHours && unfamiliar) || (unfamiliar && files >= 2))) {
      confidence = 0.97;
      reason = PATTERNS[2].name;
    } else if (count >= 5 || (unusualPort && files >= 20)) {
      confidence = 0.96;
      reason = PATTERNS[1].name;
    } else if (unfamiliar || (fullCopy && files >= 100)) {
      confidence = 0.95;
      reason = PATTERNS[0].name;
    }
  }
  if (confidence < 0.5 && !normal && (unfamiliar
      || /전송|압축|목적지|파일\s*수|명령\s*통로|transfer|destination|archive/iu.test(description))) {
    confidence = 0.6;
    reason = archive || outsideHours ? PATTERNS[2].name : count >= 2 || unusualPort ? PATTERNS[1].name : PATTERNS[0].name;
  }
  return { action: confidence >= 0.85 ? 'block' : confidence >= 0.5 ? 'alert' : 'record',
    confidence, reason };
}
