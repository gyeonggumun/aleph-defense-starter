# XDR 보너스 경보

이 폴더는 보너스 여섯 개의 연습 경보입니다. 경보는 수업용으로 만든 Wazuh 모양이며, 실제 로그가 아닙니다. 정답은 이 저장소에 없습니다.

## 경보 묶음

`xdr/fixtures/<moduleKey>.json` 을 읽습니다. `moduleKey` 는 아래 여섯 개입니다.

| moduleKey | 보는 것 |
|---|---|
| `brute-force` | 짧은 시간에 몰린 로그인 실패 |
| `web-injection` | 웹 요청에 섞인 주입 형태 |
| `known-cve` | 이미 공개된 취약점을 노린 요청 형태 |
| `persistence` | 다시 켜도 남도록 심긴 서비스·예약 작업 |
| `privilege` | 평범한 계정의 갑작스러운 권한 상승 |
| `exfiltration` | 처음 보는 곳으로 빠지는 큰 전송 |

한 파일에는 명확한 공격, 애매한 시도, 정상 이벤트가 함께 들어 있습니다. 주소는 문서용 대역만 쓰고, 계정은 `user01` 같은 가상 이름입니다. `known-cve` 의 원격 조회 구문은 문서용 표기입니다. 그 문자열을 다른 시스템에 넣거나 변형하지 않습니다.

## 학생이 만드는 파일

항목마다 `xdr/<moduleKey>/decide.mjs` 를 만듭니다. `decide(alert)` 를 내보냅니다. 비동기 함수여도 됩니다. 반환은 아래 세 값입니다.

- `action`: `block`, `alert`, `record` 중 하나
- `confidence`: 0 이상 1 이하 숫자
- `reason`: 짧은 이유

명확한 공격은 `block`, 애매한 시도는 `alert`, 정상 이벤트는 `record` 입니다. 경보 원본은 고치지 않습니다.

심판은 `decide.mjs`를 격리 실행하므로 이 파일은 단독으로 실행 가능해야 합니다. Node.js 모듈·상대 경로 파일·저장소 쓰기를 판정 모듈에서 하지 말고, 차단 규칙과 알림 기록은 `apply-actions.mjs` 또는 `respond.mjs`에서 처리합니다.

## 실행

저장소 루트에서 항목 키 하나를 넣습니다.

```
node scripts/xdr-run.mjs brute-force
```

`npm run xdr:run -- brute-force` 도 같은 명령입니다. 웹 주입은 `npm run xdr:run -- web-injection`, 알려진 취약점 악용은 `npm run xdr:run -- known-cve`입니다. 실행기는 해당 경보마다 `decide` 를 부르고, 결과를 `xdr/<moduleKey>/result.json` 에 씁니다. `brute-force`와 `web-injection`은 결정 뒤 `apply-actions.mjs`, `known-cve`는 `respond.mjs`로 만료 시각·근거 경보 ID가 있는 임시 차단 규칙과 알림 로그를 갱신합니다. 형식은 `aleph.xdr.result.v1` 이고, `decisions` 에는 경보 id·행동·확신도·이유가, `counts` 에는 `block`·`alert`·`record` 건수가 있습니다.

반환 형식이 틀린 경보는 `record` 로 남고, 오류 한 줄이 출력됩니다. 실행기 자체는 네트워크를 쓰지 않습니다. 판정자는 격리된 환경에서 같은 명령을 다시 실행해 결과를 봅니다. 이미 커밋된 `result.json` 만으로 판정이 끝나지 않습니다.

## 심판 격리 환경에서 지킬 것

심판은 인터넷 없이 `decide.mjs` 한 파일을 불러와 경보마다 바로 답을 받습니다. 이 파일이 돌지 못하면 건수를 셀 수 없어 `XDR_DECIDE_NOT_RUNNING` 으로 끝납니다.

- `decide.mjs` 에는 `import` 문을 두지 않습니다. 필요한 패턴은 `patterns.json` 에서 파일 맨 위 상수로 옮겨 적습니다.
- 파일을 읽거나 쓰지 않고, 바깥에 묻지 않고, 그 파일 안에서 혼자 계산해 답합니다. 경보 하나에 2초 안에 답합니다.
- `confidence`(확신도)는 경보가 패턴과 얼마나 뚜렷하게 맞는지를 `decide` 가 스스로 0~1 로 매긴 값입니다.
- `xdr/alerts.log` 기록과 판정기 연결은 `respond.mjs` 같은 다른 파일에서 합니다. `decide.mjs` 는 판단 결과만 돌려줍니다.

인터넷을 끈 상태에서 `npm run xdr:run -- <moduleKey>` 를 돌려도 같은 결과가 나오면 심판에서도 같은 결과가 나옵니다.

지속성 경보는 `npm run xdr:run -- persistence`로 실행합니다. `persistence/decide.mjs`의 판단 뒤 `persistence/respond.mjs`가 확인된 block만 24시간의 만료·근거 경보 ID가 있는 임시 규칙으로 연결하고 block·alert를 기존 `alerts.log` 끝에 추가합니다. 정상 이벤트는 격리하지 않습니다. `src/decider.mjs`의 `xdr.persistence_source_ip` 연결은 로컬 IP 경보 시험이며 ALEPH SDP 운영 엔진의 실제 기기 격리와 구별합니다.

권한 변경 경보는 `npm run xdr:run -- privilege`로 실행합니다. `privilege/decide.mjs`는 순수 판단만 하고 `privilege/respond.mjs`가 가명 주체와 접속 주소를 함께 대조하는 `xdr.privilege_session` 임시 규칙과 알림 기록을 처리합니다. 공개 시험 별칭의 로컬 가명은 운영 신원이 아닙니다. 실제 세션 회수에는 서버가 검증한 계정 매핑과 엔진 연결이 필요하며 미연결 결과는 not_run입니다.

외부 반출 경보는 `npm run xdr:run -- exfiltration`로 실행합니다. `exfiltration/respond.mjs`는 block 후보의 목적지 주소에만 만료·근거 경보 ID가 있는 거부 규칙을 추가합니다. `decideTransfer({request,destinationAddress})`는 기존 판정 뒤 서버가 확인한 목적지를 추가 검사하며, 출발 주소 차단과 혼동하지 않습니다. 운영 송신 경로 연결은 별도이며 현재 검증은 로컬 합성 경보입니다.
