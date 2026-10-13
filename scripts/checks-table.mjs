import config from '../aleph.config.json' with { type: 'json' };

const cell = value => String(value ?? '미실행').replaceAll('|', '\\|').replace(/[\r\n]/gu, ' ');
try {
  const response = await fetch(new URL('/api/checks', config.publicAppUrl), {
    method: 'GET', redirect: 'error', signal: AbortSignal.timeout(30000),
  });
  if (!response.ok) throw new Error(`CHECK_REPORT_HTTP_${response.status}`);
  const report = await response.json();
  if (report.schema !== 'aleph.stage12.checks.v1' || !Array.isArray(report.attempts)) {
    throw new Error('INVALID_CHECK_REPORT');
  }
  console.log(`검사 커밋: ${report.commit} · 확인 시각: ${report.checkedAt}`);
  console.log(`전체 ${report.total} · 기대 충족 ${report.blocked} · 실패 ${report.failed} · 미실행 ${report.notRun}`);
  console.log('| 단계 | 요청 | 기대 결과 | 실제 API 결과 | 결과 | 요청 상관 ID | 확인 시각 (UTC) |');
  console.log('|---|---|---|---|---|---|---|');
  for (const item of report.attempts) {
    console.log(`| ${[item.stage, item.attackId, item.expected, item.observed, item.result,
      item.requestId, item.checkedAt].map(cell).join(' | ')} |`);
  }
} catch (error) {
  console.error(`실측 표 조회 실패: ${error.message}`);
  process.exitCode = 1;
}
