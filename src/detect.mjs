// 반 엔진이 검증한 가명 사건만 전달해야 하며, 브라우저가 보낸 사용자 번호는 받지 않습니다.
const WINDOW_MS = 10 * 60 * 1000;
const READ_LIMIT = 120;

export function detect(events) {
  if (!Array.isArray(events)) throw new TypeError('invalid_detection_events');

  const readsBySubject = new Map();
  for (const event of events) {
    if (event?.method !== 'GET' || typeof event.at !== 'string') continue;
    const subject = event.identity?.sub;
    if (typeof subject !== 'string' || !subject) continue;
    const at = Date.parse(event.at);
    if (!Number.isFinite(at)) continue;
    if (!readsBySubject.has(subject)) readsBySubject.set(subject, []);
    readsBySubject.get(subject).push(at);
  }

  for (const [subject, times] of readsBySubject) {
    times.sort((left, right) => left - right);
    let first = 0;
    for (let last = 0; last < times.length; last++) {
      while (times[last] - times[first] > WINDOW_MS) first++;
      if (last - first + 1 > READ_LIMIT) {
        return { action: 'propose_revocation', reasonCode: 'burst_read', subject };
      }
    }
  }
  return { action: 'observe' };
}
