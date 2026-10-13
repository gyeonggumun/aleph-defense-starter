# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

1단계 시작 당시에는 `/`에서 점령된 가상 자료실을 보고 `/data.json`에서 같은 가상 메모를 읽을 수 있었습니다. 2단계에서 바뀐 현재 상태와 남은 공개 범위는 아래에 기록합니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 2단계: 서버 API로 가상 자료 읽기

현재 `data.json`과 `public/data.json`의 `notes`는 비어 있습니다. 정적 화면은 `/api/notes`를 호출하고, 서버 함수가 Supabase의 `public.vault_notes`에서 가상 메모 네 건을 읽습니다. `SUPABASE_URL`과 `SUPABASE_SECRET_KEY`는 Vercel 프로젝트의 서버 환경변수로만 등록합니다. 키 값은 저장소, 브라우저 코드, README, 로그, 제출 묶음에 넣지 마세요.

현재 Vercel 배포 주소: https://aleph-defense-starter-ten.vercel.app

`vault_notes`에는 `owner_id uuid`가 있으며 `auth.users` 외래키는 없습니다. RLS를 켜고 `anon`, `authenticated`, `public`의 테이블 권한을 모두 회수하며, 서버 함수에서만 사용하는 `service_role`에 읽기 권한을 줍니다. 이 단계의 `/api/notes`는 로그인 없이 열려 있으므로 가상 자료만 유지해야 합니다.

### 2단계에서 직접 확인할 항목

1. 배포된 화면에 가상 메모 네 건이 보입니다.
2. 배포된 `/api/notes`를 비로그인으로 열면 가상 자료 네 건이 반환됩니다.
3. 배포된 `/data.json`의 `notes` 배열은 비어 있고 1단계 확인 표시 `SAMPLE_NOTE_1`도 없습니다.
4. GitHub 기본 브랜치의 `data.json`과 `public/data.json`을 열고, GitHub 코드 검색으로 가상 메모 제목과 본문을 각각 검색해 최신 파일에 남지 않았는지 확인합니다.
5. 이전 공개 커밋과 과거 Vercel 배포는 이 변경으로 삭제되거나 비공개 처리되지 않습니다. 과거 노출까지 해결됐다고 간주하지 마세요.

로컬 정적 확인은 `node scripts/build-public.mjs --local`로 합니다. 이 명령은 배포나 API 연결을 증명하지 않습니다. 제출 묶음은 2단계 저장점 커밋 뒤 `bundle-notes.json`에 실행한 점검 결과만 적고 `npm run bundle`을 실행합니다.

## 3단계: 진짜 로그인과 메모 관리

Supabase Auth의 공식 JavaScript SDK로 이메일·비밀번호 로그인과 로그아웃을 제공합니다. 프로젝트 URL과 publishable key는 브라우저에서 사용하는 공개 값입니다. `SUPABASE_SECRET_KEY`는 Vercel 서버 환경변수에서만 읽습니다. 서버는 `src/verify-login.mjs`로 토큰을 검증하고, 브라우저가 보낸 사용자 ID나 역할은 사용하지 않습니다.

로그인한 사용자는 `/api/notes`에서 메모 목록을 보고 추가할 수 있으며, `/api/notes/:id`에서 한 건을 읽고 수정하거나 삭제할 수 있습니다. 새 메모의 `owner_id`는 서버가 확인한 사용자 ID입니다. 이전 단계의 소유자 없는 가상 메모 네 건도 로그인 화면에서 계속 볼 수 있습니다. 3단계에서는 단건 경로에 소유자 검사가 없으므로 로그인한 다른 사용자가 ID를 알면 남의 메모를 읽고 바꾸거나 지울 수 있습니다. 이 접근 제어는 4단계에서 추가합니다.

`aleph.config.json`에는 Supabase Auth 발급자·대상·JWKS 주소와 실제 GET·POST·PUT·DELETE 경로를 기록합니다. 발급자 주소는 공개 정보이며 비밀 키는 기록하지 않습니다. `vercel.json`은 `/api/notes/:id`를 Vercel 함수로 연결하고, 첫 화면에 `X-Content-Type-Options: nosniff`를 계속 붙입니다.

3단계 저장점에서는 `npm run bundle`이 실제 배포의 비로그인 API 응답, 빈 공개 `data.json`, `/aleph.json`, 첫 화면 보안 헤더를 조회합니다. 이 자기 점검은 메모를 변경하지 않으며 실제 계정 로그인과 CRUD는 배포 화면에서 확인합니다.

마지막 3단계 저장점 커밋은 제출 자기 점검의 배포 주소 비교를 보정했습니다. 인증·자료 API 동작은 바꾸지 않았습니다.

## 4단계: 로그인 사용자의 메모만 허용

`src/notes-api.mjs`는 토큰에서 서버가 검증한 `identity.userId`만 소유자 기준으로 씁니다. 목록·단건 조회·수정·삭제는 모두 `owner_id`가 이 ID인 행만 대상으로 하며, 수정은 기존 행과 반환된 새 행의 소유자를 확인합니다. 추가할 때도 본문에 적힌 `owner_id`는 사용하지 않고 검증된 사용자 ID를 저장합니다. 다른 사용자 메모와 없는 메모는 같은 `404 NOT_FOUND` JSON으로 응답합니다. `aleph.config.json`에는 실제 GET·POST·PUT·DELETE 경로를 유지합니다.

현재 `public.vault_notes`는 RLS가 켜져 있고, 마지막 읽기 전용 확인 시 `anon`과 `authenticated`의 직접 테이블 권한은 없었습니다. 서버 API는 기존 서버 전용 키를 사용합니다. authenticated 역할에 CRUD 권한과 소유자별 RLS 정책을 적용하는 SQL은 제안만 하며, DB에는 실행하지 않았습니다. 사용자가 SQL Editor에서 제안 SQL을 검토·실행한 뒤 `information_schema.role_table_grants`와 `has_table_privilege` 결과를 확인해야 합니다.

4단계 과제 설명은 기존 메모 세 건을 전제로 하지만 실제 테이블에는 네 건이 있습니다. 소유자 지정 SQL은 오래된 세 행의 ID 미리보기를 먼저 보여 주고, A/B 이메일을 SQL Editor에서 직접 채우도록 합니다. 미리보기에서 A로 지정할 세 건이 맞는지 확인한 뒤 실행하세요. 현재 네 행은 하나의 owner_id에 연결되어 있으나 그 계정이 A인지 B인지는 확인하지 않았습니다. B용 가상 시험 메모 SQL도 제안만 했으며 아직 추가하지 않았습니다.

### 4단계에서 직접 확인할 항목

1. A로 로그인해 자기 메모 목록·단건 조회·추가·수정·삭제를 확인합니다.
2. B로 로그인해 A의 메모 ID를 요청해 읽기·수정·삭제가 모두 404로 거부되는지 확인합니다.
3. 요청 본문에 다른 `owner_id`를 넣어도 새 메모는 로그인 사용자 소유로 저장되고, 기존 메모 소유권은 바뀌지 않는지 확인합니다.
4. 익명 `/api/notes` 요청이 401/403 JSON 오류인지, `/data.json`의 `notes`가 비어 있는지, `/aleph.json`의 단계가 4인지, 첫 화면에 `nosniff` 또는 CSP가 있는지 번들 점검합니다.

## 5단계: 메모 자료 요청을 서버로 모으기

브라우저 코드에서 Supabase 테이블을 직접 조회·변경하는 `.from(...)` 호출은 없습니다. 메모 목록·단건 조회·추가·수정·삭제는 같은 출처의 `/api/notes`와 `/api/notes/:id`를 호출합니다. Supabase Auth SDK의 로그인·로그아웃 호출은 유지하고, 인증 요청은 `/api/auth`가 중계하며 서버 함수의 `SUPABASE_SECRET_KEY`만 사용합니다. 실제 Supabase API 키는 화면 코드에 없습니다. 메모 API는 서버에서 토큰과 `owner_id`를 계속 검증합니다.

`aleph.config.json`의 `originalApiUrl`은 쿼리 문자열이 없는 `https://wypzkqzsgnnzpjcztlbz.supabase.co/rest/v1/vault_notes`입니다. 현재 읽기 전용 확인에서 `anon`·`authenticated`에는 테이블 권한이 없었고, RLS는 켜져 있었습니다. 직접 권한을 명시적으로 회수하는 SQL은 저장소 밖의 `outputs/step5-revoke-public-data-access.sql`에 있으며 아직 적용하지 않았습니다. 이 SQL은 `public.vault_notes`만 대상으로 하며 서버 전용 키의 권한은 건드리지 않습니다.

Supabase Auth SDK의 `signInWithPassword`와 `signOut` 호출은 유지합니다. SDK의 사용자 인증 요청은 같은 출처의 `/api/auth`가 서버에서 중계하고, 비밀번호 로그인·세션 갱신·로그아웃만 허용합니다. `SUPABASE_SECRET_KEY`는 서버 함수가 `apikey` 헤더에만 넣으며 화면 코드에는 Supabase API 키가 없습니다. 중계기는 인증 외 경로, 과도한 자격 증명 본문, 16 KiB 초과 요청을 거부합니다. 메모 CRUD는 계속 `/api/notes`에서 로그인·소유자를 확인합니다.

### 5단계에서 직접 확인할 항목

1. SQL Editor에서 권한 회수 SQL의 전후 조회를 확인하고 실행합니다. 기대 결과는 `anon`·`authenticated` 모두 테이블 권한이 없는 것입니다.
2. 브라우저에서 A로 로그인해 메모 CRUD가 `/api/notes` 서버 함수를 통해 계속 동작하는지 확인합니다.
3. B의 타인 메모 요청은 계속 404로 거부되고 비로그인 요청은 401/403 JSON 오류인지 확인합니다.
4. 공개 anon key로 원본 `originalApiUrl`을 요청해 행이 반환되지 않는지 심판과 직접 확인합니다.
5. `/aleph.json`의 허용 경로, 첫 화면 보안 헤더, 공개 `data.json`의 빈 `notes`를 번들 점검합니다.

## 보너스 XDR: 무차별 로그인 공격 경보

`xdr/brute-force/read-alerts.mjs`는 `xdr/fixtures/brute-force.json`에서 시각·출발 주소·계정·Wazuh 규칙 수준·설명만 추려 비밀값처럼 보이는 문자열을 가립니다. `patterns.json`은 MITRE ATT&CK T1110에 근거한 같은 주소의 반복 실패와 여러 계정 대상 비밀번호 대입 두 신호만 정의합니다.

`npm run xdr:run -- brute-force`로 시험합니다. 실행 결과는 `xdr/brute-force/result.json`, 일시 차단 규칙은 `xdr/brute-force/deny-rules.json`, 알림 기록은 `xdr/alerts.log`에 씁니다. 차단 규칙은 확신도 0.85 이상일 때만 추가하고 24시간 뒤 만료되며 근거 경보 번호를 포함합니다. 반복 실행은 같은 경보의 로그·규칙을 중복 추가하지 않습니다. `decide()`는 원본 경보와 정규화 경보를 모두 받는 단독 실행 모듈이고, 차단 규칙·알림 기록은 별도 `apply-actions.mjs`가 처리합니다. 현재 명확한 차단 조건은 규칙 수준 10 이상에서 같은 주소의 로그인 실패가 20건 이상이거나, 같은 비밀번호가 여러 계정에 시도된 경우입니다.

`src/decider.mjs`는 자료실 읽기 이외의 요청에 `starter.deny`를 적용하고, 확인된 `request.signals.source`가 유효한 출발 IP이며 일시 차단 규칙과 일치할 때 `xdr.brute_force_source_ip`를 적용합니다. 현재 운영 판정 요청의 `signals.source`는 `none`이므로, 운영에서 실제 IP 차단을 하려면 신뢰된 출발 주소를 판정 요청 계약에 전달하는 별도 운영 측 연결이 필요합니다. 이 저장소의 fixture 실행은 운영 트래픽 차단을 증명하지 않습니다.

애매한 경보에만 `globalThis.Jev.reviewBruteForceAlert({ alert, pattern })` 어댑터를 호출합니다. 이 실행 환경에 Jev 응답자가 없거나 1.5초 안에 응답하지 않으면 `alert`로 남기며, 어댑터에는 정제된 다섯 필드만 전달합니다. 실행 명령은 네트워크를 사용하지 않습니다.

확인 명령은 `node xdr/brute-force/read-alerts.mjs`와 `npm run xdr:run -- brute-force`입니다. 첫 명령의 출력 줄 수가 경보 수와 같아야 하며, 두 번째 결과에서 block·alert·record를 확인하고 정상 경보가 block되지 않는지 봅니다.

## 보너스 xdr-02 저장점 · 웹 주입

- `node xdr/web-injection/read-alerts.mjs`: 원본 26건을 시각·주소·계정·수준·설명 26줄로 정제합니다. 비밀값 마스킹은 기존 읽기 모듈을 재사용하고 원본은 수정하지 않습니다.
- `patterns.json`은 [MITRE ATT&CK T1190](https://attack.mitre.org/techniques/T1190/)을 근거로 SQL·스크립트·경로 이탈·명령 주입 신호와 애매한 입력을 구분합니다. 동일 주소 8회 이상·수준 10 이상은 학습용 기준입니다. Wazuh의 집계 횟수를 읽으며 독립 단일 경보 사이의 시간창 집계기는 아닙니다.
- `decide.mjs`는 import 없이 원본·정제 입력과 격리 환경을 지원합니다. 애매한 요청만 `globalThis.Jev.reviewWebInjectionAlert({pattern, ruleLevel, count})` 또는 `review`로 검토합니다. 연결 없음·실패·1.5초 초과 시 confidence 0.5의 alert입니다. 실제 Jev 연결은 제공되지 않아 로컬 시험은 대체 응답자와 실패 처리를 검증했습니다. 반복 증거 없는 요청은 모델 점수가 높아도 0.84 이하로 제한합니다.
- `npm run xdr:run -- web-injection`: `result.json`, 근거 경보 번호·24시간 만료를 갖는 `deny-rules.json`, `xdr/alerts.log`를 갱신합니다. 기존 무차별 로그인 규칙과 로그는 보존합니다.
- 로컬 결과: **block 8 / alert 9 / record 9, 정상 경보 차단 0**. 26건의 개별 판정, 단독 import·빈 VM 실행, Jev 실패, 만료·정상 주소 허용을 시험했습니다. 실제 심판 점수는 재제출 후 확인해야 합니다.
- 판정기는 웹 주입 규칙을 추가로 읽습니다. 6단계부터 등록 기기의 자료실 읽기를 허용하며, 일치하는 XDR 규칙은 계속 거부합니다. 실제 계약의 `signals.source`가 `none`인 운영 경로에는 검증된 출발 주소 연결이 추가로 필요합니다.
- `aleph.config.json`의 기존 5단계 자료실 설정·발급자·경로·원본 주소는 이 보너스가 변경하지 않습니다.

## 6단계 저장점 · 등록한 기기만 자료실 읽기

`docs/DECIDER_REQUEST.md`의 `subjectId`는 운영 엔진이 확인한 가명 사용자이고, `deviceRegistered`는 그 엔진이 확인한 기기 등록 여부입니다. 판정기는 등록값이 정확히 `true`이고 `service: notes`의 `GET /notes` 또는 `GET /notes/:id` 요청일 때만 `allow`·`approved`를 돌려줍니다. 미등록·누락은 `deny`·`device_not_registered`이며, 기존 XDR 임시 거부 규칙이 일치하거나 다른 동작·경로이면 거부합니다. 브라우저 화면과 자료 API는 바꾸지 않았습니다.

저장소에서 `npm run decider:test`를 실행해 「등록 기기의 정상 요청」 통과와 「미등록 기기의 가상 요청」 거부를 확인합니다. `npm run bundle`은 저장점 커밋 뒤 제출 JSON을 생성합니다. 실제 등록 기기 화면 접근과 미등록 기기 공격 판정은 운영 엔진·심판에서 따로 확인해야 하며, 설치 프로그램이나 기기 개인키를 이 저장소에 추가하지 않았습니다.

### 6단계 재검증 · 판정기 단독 실행

심판 화면의 `S06_DEVICE_RULE_MISSING`은 이전 커밋 `15b7294`를 대상으로 했습니다. 해당 판정기는 기기 검사 전에 XDR 모듈·파일을 읽었으며, 판정기 파일만 가져오는 실행에서 상대 import 해석 실패를 재현했습니다. 현재는 등록값이 정확히 true가 아니면 즉시 `deny/device_not_registered`를 반환하고, 계약의 `none/judge_fixture` 요청은 외부 파일 없이 판정합니다. 로컬 IP 시험용 XDR 연결은 필요할 때만 읽고 읽기 실패 시 거부합니다.

경로 검사도 유지합니다. 계약에 UUID 전용 조건이 없는 판정기에서는 `/notes/demo` 같은 단일 ID를 허용하며, 실제 메모 API의 UUID·소유자 검사는 유지합니다. `/notes/export`, 추가 하위 경로, 경로에 붙인 쿼리는 거부합니다. `npm run decider:test`는 기존 6·7단계 시험과 함께 단독 파일·격리 VM의 등록/미등록/누락/문자열/위조 헤더 시험을 실행합니다. 로컬 통과는 실제 심판 통과를 뜻하지 않으며, 최신 커밋으로 재제출해야 합니다.

## 7단계 저장점 · 복합 이상 접속 다시 확인

`src/decider.mjs`는 엔진 계약의 `signals.source === 'judge_fixture'`인 가상 사건에서만 시각·네트워크·최근 행동을 평가합니다. 22~05시, 처음 보는 네트워크, 5분 이내 `risk_signal` 10건 이상이 함께 있으면 `step_up`·`step_up_required`로 다시 확인을 요청합니다. 지역 하나만으로 차단하지 않고 클라이언트 헤더를 판정 입력으로 읽지 않습니다. 신호가 없거나 출처가 불명확할 때 정상 지역·시각으로 채우지 않으며, 실제 `source: none` 경로의 위치 정보로 간주하지 않습니다. 기존 기기 등록과 XDR 거부 규칙은 유지합니다.

계약에는 엔진이 전달하는 `stepUp.verified`와 `authAgeSeconds`가 있으므로 가상 사건에서는 확인 전 `step_up`, 확인된 새 요청에서 로그인 나이 300초 이내면 `allow`로 다시 판정합니다. 문서에는 그 시각이 **같은 로그인 주체**에 연결된다는 운영 보증과 실제 재로그인 시험 경로가 명시되지 않았습니다. 따라서 실제 자료 차단·해제는 미실행입니다. 이 값만으로 브라우저 로그인을 대신 검증했다고 주장하지 않습니다.

로컬 확인 순서: `npm run decider:test`로 등록·미등록·복합 위험·다시 확인한 가상 요청을 검사한 뒤 `npm run fixture:7`로 정상 `allow`와 복합 위험 `step_up`을 확인합니다. 저장점 커밋 뒤 `npm run bundle`로 제출 묶음을 갱신합니다. 브라우저 화면·자료 API·비밀 설정은 바꾸지 않았습니다.

## 8단계 저장점 · 자료 자원 구역

`src/decider.mjs`는 엔진이 확인한 `service`·`method`·`route`·정확한 `path`가 맞는 읽기만 허용합니다. 로그인 사용자의 메모 목록은 소유자 필터를 적용하는 `GET /api/my/notes`로 분리했습니다. 기존의 모호한 `GET /api/notes` 목록과 모든 쓰기 요청은 판정기에서 거부합니다. 단건 메모 읽기는 최종 API가 검증된 로그인 ID와 저장된 `owner_id`를 다시 대조합니다. 알 수 없는 경로, 쿼리가 붙은 경로, `export` 같은 비자료 경로도 거부합니다. 등록 기기·XDR·복합 위험 규칙은 유지합니다.

학습 DB에는 `sql/stage8-instructor-notices.sql`의 `public.instructor_notices`와 가상 공지 한 건을 적용했습니다. RLS는 켜져 있고 `PUBLIC`·`anon`·`authenticated`의 테이블 권한은 회수했습니다. `/api/notices`와 `/api/notices/:id`의 읽기는 검증된 로그인만 허용합니다. 공지 수정은 `src/notices-api.mjs`가 Supabase Auth Admin에서 확인한 계정의 `app_metadata.role === 'instructor'`일 때만 허용하며, 본문의 `role`과 `user_metadata`는 무시합니다. 거부는 JSON 401·403·404로 짧게 돌려줍니다.

**경로 정책:** `aleph.config.json`의 `allowedRoutes`에는 `GET /api/my/notes`, `GET /api/notes/:id`, `GET /notes/:id`만 정확한 서비스·메서드·경로 패턴으로 등록합니다. 판정 계약에는 메모 소유자나 강사 역할 증거가 없으므로 판정기에서 모호한 목록과 쓰기를 허용하지 않습니다. 앱의 메모 추가·수정·삭제 API는 별도로 로그인한 사용자의 ID를 저장·대조하고, 공지 수정 API는 Supabase에서 확인한 `app_metadata.role`을 검사합니다. 브라우저 본문의 `owner_id`·`role`은 권한 근거로 사용하지 않습니다.

현재 `docs/DECIDER_REQUEST.md`에는 가명 `subjectId`와 메모의 소유자 ID를 연결하는 계약이 없습니다. 따라서 판정기는 소유자를 추측하지 않고, 메모 API가 검증된 Supabase 사용자 ID로 소유권을 다시 검사합니다. 실제 A/B 계정과 강사 계정으로 한 운영 실측은 미실행이며, 로컬 가상 시험을 심판의 100점 판정으로 간주하지 않습니다.

로컬 확인은 `node --test test/stage8.test.mjs`, `npm run decider:test`, `npm run fixture:7` 순서로 수행합니다. 이 시험은 가상 요청이며 실제 A/B 계정의 UI 접근이나 운영 판정기를 증명하지 않습니다. 변경 저장점 뒤 `npm run bundle`로 제출 JSON을 생성합니다.

## 9단계 저장점 · 가상 조회 폭주 탐지

`src/detect.mjs`의 `detect(events)`는 엔진이 검증해 전달한 사건에서 시각(`at`), 요청 종류(`method`), 가명 사용자(`identity.sub`)만 읽습니다. 같은 사용자의 `GET`이 어느 10분 구간에서든 120건을 넘으면 별도 탐지 결과 `{ action: 'propose_revocation', reasonCode: 'burst_read', subject }`를 반환하고, 그 밖에는 `{ action: 'observe' }`를 반환합니다. 서로 다른 사용자의 사건을 합산하지 않으며, 메모 본문·토큰·실명은 읽거나 기록하지 않습니다. 기존 `decide(request)`의 허용·거부 응답과 자료 API는 바꾸지 않습니다.

현재 `docs/DETECT_EVENTS.md` 계약에는 검증된 기기 ID·네트워크·기존 판정이 없습니다. 따라서 네트워크 이상과 특정 기기 한 대의 회수 대상은 이 입력으로 확인할 수 없습니다. 탐지 결과는 가명 사용자에 대한 **제안**이며 실제 기기 권한 회수와 탐지부터 회수까지의 시간 측정은 운영 엔진·심판에서 미실행입니다. 정상 조회와 정확히 120건은 `observe`로 유지합니다.

확인은 `npm run detect:test`로 정상·경계·폭주·사용자 분리·시간 구간을 시험합니다. 저장점 커밋 뒤 `npm run bundle`로 제출 묶음을 갱신합니다. 로컬 시험 통과를 실제 접속 회수나 심판 판정으로 간주하지 않습니다.

## 10단계 저장점 · 검증된 사본으로 시험 복구

**현재 상태:** 침해 전 검증된 정책·비공개 메모 사본이 제공되지 않았고, 학습 DB의 메모 4건은 모두 같은 소유자에게 속합니다. B 소유 복구 대상은 확인되지 않았습니다. 따라서 실제 정책·메모 복원과 복원 뒤 운영 재시험은 **미실행**입니다. 현재 자료를 새로 저장해 침해 전 백업이라고 부르지 않습니다.

### 정책 사본의 차이 확인과 시험 복원

`scripts/recover-policy.mjs`는 운영 `src/decider.mjs`를 수정하지 않습니다. 외부에 보관한 `aleph.test-policy.v1` JSON 사본과 별도의 `*.trial.json` 시험 정책을 받습니다. 둘 다 `services.notes`를 갖고 있어야 합니다. 사본을 침해 전에 검증하며 기록한 SHA-256과 다시 대조한 뒤 `services.notes`의 변경 전후만 출력합니다. 사본 부재·해시 불일치·형식 오류에서는 중단합니다. 적용 시 다른 서비스 정책과 `audit` 필드는 그대로 둡니다.

1. 신뢰한 위치에서 사전에 기록한 사본 SHA-256을 확인합니다. 정책 본문이나 해시를 공개 저장소에 넣지 않습니다.
2. `node scripts/recover-policy.mjs preview <비공개-사본.json> <현재-정책.trial.json> <사전기록-SHA256>`로 복원 버전과 notes 범위를 확인합니다.
3. 범위를 검토한 뒤에만 `node scripts/recover-policy.mjs apply <비공개-사본.json> <현재-정책.trial.json> <사전기록-SHA256> <같은-SHA256>`을 실행합니다. 운영 판정기와 감사 파일에는 쓰지 않습니다.
4. 복원한 시험 정책을 실제 판정기에 연결하는 별도 운영 계약은 현재 제공되지 않았습니다. 로컬 시험 정책 파일 갱신을 운영 정책 복구로 기록하지 않습니다.

### 비공개 메모 한 건 복원

Vercel `notes` 서비스의 `POST /api/restore-note`는 `aleph.config.json`의 `restoreRoute`에 기록했습니다. 서버 전용 설정 `RESTORE_NOTE_BACKUP_JSON`은 침해 전에 보관한 **B의 메모 한 건** `{id,owner_id,title,content,content_sha256}`의 JSON 원문이고, `RESTORE_NOTE_BACKUP_SHA256`은 그 원문의 사전에 검증한 SHA-256, `RESTORE_B_USER_ID`는 검증된 B의 UUID입니다. 이 값과 메모 본문은 브라우저 코드·Git·로그·응답에 넣지 않습니다. 서버 설정이 없거나 원문·내용 해시가 틀리면 쓰기 전에 중단합니다.

1. B로 로그인한 뒤 `{ "id": "<대상 UUID>", "confirm": false }`를 POST해 현재·사본 내용 해시, 소유자, 제목 변경 여부만 미리 확인합니다. 응답은 본문을 내보내지 않습니다.
2. ID·소유자·변경 범위가 맞을 때만 같은 경로에 `{ "id": "<대상 UUID>", "confirm": true, "expectedCurrentSha256": "<미리보기 값 또는 null>", "expectedContentSha256": "<미리보기 사본 해시>" }`를 보냅니다. 서버는 검증한 B 신원과 DB 소유자를 확인하고 해당 ID 한 행만 갱신하거나 되살립니다. 현재 행이 바뀌었거나 타인 소유가 되었다면 거부합니다.
3. 결과의 ID·소유자·내용 SHA-256을 사본과 비교하고, 다른 메모 및 감사 기록이 보존됐는지 별도로 확인합니다. 비로그인·A 계정은 401·403이어야 합니다. 실제 사본이 없으므로 이 절차는 현재 **미실행**입니다.

### 복원 뒤 재시험 순서

1. 1~2단계: 공개 `/data.json`의 빈 메모, GitHub 최신 파일, `/aleph.json`, 보안 헤더 및 옛 공개 이력의 한계를 확인합니다.
2. 3~5단계: 비로그인 메모 API 거부, A 정상 CRUD, B의 A 메모 읽기·수정·삭제 거부, 원본 Data API의 anon 직접 권한 회수를 확인합니다.
3. 6~8단계: `npm run decider:test`로 등록·미등록 기기와 복합 이상 사건, 본인 메모 허용·타인 메모/학생 공지 수정 거부를 확인합니다. 실제 A/B API 요청도 별도로 재확인합니다.
4. 9단계: `npm run detect:test`로 정상 사건 유지와 복합 의심 사건의 회수 **제안**만 확인합니다. 실제 회수는 엔진 시험으로 확인합니다.
5. 복원 대상 행과 시험 정책의 해시, 다른 서비스 규칙과 감사 이력의 불변 여부를 최종 대조합니다. 이 순서 중 실제 수행하지 않은 운영 확인은 계속 **미실행**으로 기록합니다.

로컬에서 `node --test test/stage10.test.mjs`는 사본 해시 오류 중단, 시험 정책의 notes 범위 갱신, B 신원·해시 확인, 다른 메모 보존을 가상 데이터로 검사합니다. 이 시험은 없는 사전 백업이나 실제 복원을 증명하지 않습니다.

## 11단계 · 설치형 화면과 기기 승인

`public/manifest.webmanifest`와 192·512px 아이콘을 추가해 기존 배포 주소를 홈 화면 앱으로 열 수 있게 했습니다. `public/sw.js`는 오프라인 안내 페이지만 저장합니다. 보호 자료·인증 응답·기기 승인 상태는 캐시에 저장하지 않으며, 오프라인에서는 자료실 대신 안내 화면이 나옵니다. 화면에도 설치 표시가 기기 승인을 뜻하지 않는다고 적었습니다.

Supabase Auth 세션의 영구 브라우저 저장을 끄고 이전 버전의 저장 항목을 제거합니다. 새로고침 후에는 다시 로그인해야 할 수 있습니다. 로그인·소유자·강사 권한 검사는 유지합니다.

로그인 후 기기 등록 요청 버튼은 WebAuthn 보안 장치의 공개 키를 **승인 대기**로 저장할 뿐 자료 권한을 주지 않습니다. 서버가 기기 바인딩과 사용자 확인을 검증하고, 관리자가 별도로 승인한 자격 증명만 다음 확인에 사용합니다. 서버는 승인된 기기의 새 WebAuthn 서명을 검증한 뒤 5분짜리 자료 접근 증명을 발급합니다. 이 증명은 화면 메모리에만 두고 저장소·서비스 워커 캐시·URL에는 넣지 않습니다. 메모·공지·복원 API는 로그인과 서버 승인 기록을 매 요청 확인하며, 증명이 없거나 철회되었으면 JSON `403 DEVICE_NOT_APPROVED`를 반환합니다. 설치 표시와 버튼 클릭은 승인 결과가 아닙니다.

`sql/step11-device-approval.sql`은 `device_credentials`와 일회용 `device_challenges`를 만들고 두 테이블의 anon·authenticated 직접 권한을 회수합니다. 학습 DB에 적용했고 두 테이블의 RLS가 켜져 있으며 anon·authenticated의 SELECT가 없고 service_role의 SELECT가 있음을 확인했습니다. 관리자 승인 전에는 기존 사용자도 자료를 볼 수 없게 되는 것이 의도한 기본 거부 동작입니다. 기기 승인 절차는 다음과 같습니다.

1. 배포 화면에서 로그인하고 **기기 등록 요청**을 눌러 이 기기의 보안 장치 확인을 마칩니다. 화면은 승인 대기를 표시하며 메모는 계속 숨깁니다.
2. 관리자는 Supabase SQL Editor에서 `select credential_id, owner_id, status, created_at from public.device_credentials where status = 'pending' order by created_at;`로 대기 기록을 확인합니다. 사용자와 기기를 별도 경로로 확인한 뒤 해당 한 건만 `update public.device_credentials set status = 'approved' where credential_id = '<확인한 ID>' and owner_id = '<확인한 사용자 UUID>' and status = 'pending' returning credential_id, status;`로 승인합니다. 사용자 본문·개인키는 SQL 결과에 없습니다.
3. 사용자는 **승인된 기기 확인**을 눌러 보안 장치로 서명합니다. 서버의 검증이 성공해야 메모 영역과 기존 CRUD 화면이 열립니다. 승인을 취소할 때는 관리자가 해당 기록을 `revoked`로 바꾸면 새 API 요청이 거부됩니다.

운영 판정 엔진의 `deviceRegistered` 계약을 이 웹 승인 DB에 연결하는 별도 계약은 제공되지 않았습니다. 웹 자료 API의 승인 검증과 엔진 판정은 각각 독립적으로 유지하며, 엔진의 실제 승인 확인까지 시험했다고 주장하지 않습니다. 동기화된 다중 기기 패스키는 기기 바인딩 보증이 약하므로 등록을 거부합니다.

확인 순서: `node --test test/stage11-device.test.mjs`와 `node scripts/build-public.mjs --local`을 실행합니다. 배포 후 `/manifest.webmanifest`가 열리는지, 로그인 전 자료가 없는지, 로그인만 한 `/api/my/notes` 요청이 `403 DEVICE_NOT_APPROVED`인지, 대기 상태 화면에 자료가 없는지, 관리자 승인과 기기 확인 뒤 자신의 메모 CRUD가 되는지 직접 확인합니다. 다른 기기·승인 취소 뒤의 동일 API는 거부되어야 합니다. 실제 기기 등록·관리자 승인·배포 후 화면 시험은 수행한 경우에만 완료로 기록합니다.

## 12단계 저장점 · 탈환 작전실

### 작전실과 결과의 출처

로그인하고 서버가 발급한 5분짜리 승인 기기 증명이 있을 때 자료실 아래 **탈환 작전실**에서 `/api/operations`의 실제 JSON 응답을 조회합니다. 응답은 메모 본문·메모 ID·소유자 ID·WebAuthn 자격 증명을 포함하지 않습니다. 현재 사용자 메모 개수와 기기 상태는 서버 DB에서 다시 조회합니다. API 응답에 요청 ID와 UTC 확인 시각을 붙여 표에 그대로 표시합니다.

작전실은 `src/decider.mjs`의 규칙 ID와 학생 판정기의 합성 정상/미등록 요청 결과를 구분해 보여 줍니다. 실제 탐지 사건 스트림은 연결되어 있지 않아 사건 수와 탐지 결과를 **미실행**으로 표시합니다. 임의의 사건 수를 운영 수치처럼 표시하지 않습니다. ALEPH SDP 엔진의 감사 기록 스트림도 연결되어 있지 않으므로 과거 엔진 판정은 미실행입니다. 이 화면이나 API는 실제 기기 권한을 바꾸지 않습니다.

복구 카드에는 배포 커밋, 메모 백업의 해시·소유자 검증 상태, 정책 사본 상태를 표시합니다. 정책 사본과 사전 검증 메모 사본이 없으면 `unavailable`/미실행으로 보입니다. 백업 본문, ID, 소유자 및 해시는 브라우저로 보내지 않습니다. 실행 가능한 1~11단계 증거 행렬과 기록 절차는 [docs/OPERATIONAL-EVIDENCE.md](docs/OPERATIONAL-EVIDENCE.md)에 있습니다. 현재 미실행으로 표시된 행이나 심판의 **41종 공격**은 성공으로 계산하지 않습니다.

### 설치·실행·중지·복구

학생이 만든 판정기는 `src/decider.mjs`, 탐지 규칙은 `src/detect.mjs`, 브라우저 앱은 `public/`, 서버 API는 `api/`에 있습니다. 로그인 검증, Supabase 데이터베이스·배포, 앱 요청 중계와 실제 보호 요청 실행은 제공된 **ALEPH SDP 엔진/호스팅 환경**의 역할입니다. 엔진 요청 계약은 [docs/DECIDER_REQUEST.md](docs/DECIDER_REQUEST.md)에 기록했으며, 엔진 비밀값이나 소스는 이 저장소에 넣지 않았습니다.

1. 개발 의존성을 설치하려면 저장소 루트에서 `npm ci`를 실행합니다. `node --version`은 `>=22`여야 합니다.
2. 판정기·탐지기의 로컬 합성 시험은 `npm run decider:test`, `npm run fixture:7`, `npm run detect:test`로 실행합니다. XDR 합성 경보는 `npm run xdr:run -- brute-force` 또는 `npm run xdr:run -- web-injection`으로 확인합니다. 결과는 실제 운영 엔진의 판정이 아닙니다.
3. 정적 화면만 만들 때는 `node scripts/build-public.mjs --local`을 실행하고 `public/`을 확인합니다. 이는 서버 함수, 로그인, DB 또는 운영 배포를 시작하지 않습니다. 전체 로컬 API를 시험하려면 연결된 Vercel 프로젝트의 환경 설정이 필요하며 `npx vercel dev`로 실행합니다. 서버 키는 Vercel 환경 변수에서만 읽고 소스·브라우저·Git에 복사하지 않습니다.
4. 배포 앱은 [설정된 자료실 주소](https://aleph-defense-starter-ten.vercel.app)에서 열 수 있습니다. 별도 접속 프로그램은 없습니다. 홈 화면 설치는 선택 사항이며 기기 승인이 아닙니다. 로그인 후 기기 등록 대기, 관리자의 별도 승인, 보안 장치 확인이 모두 끝나야 자료실과 작전실이 열립니다.
5. 로컬 Vercel 서버는 실행 터미널에서 `Ctrl+C`를 눌러 중지합니다. 웹 앱은 탭을 닫거나 로그아웃합니다. 로그아웃·승인 만료·철회 뒤 브라우저 화면은 보호 자료를 비웁니다.
6. 되돌릴 때 먼저 `git status`와 `git diff`를 확인한 뒤 단계 커밋을 `git revert <12단계-커밋>`으로 되돌립니다. `reset --hard`는 쓰지 않습니다. DB 행과 감사 기록은 Git 되돌리기에 포함되지 않습니다. 운영 정책은 사전 고정 SHA-256으로 검증한 별도 사본이 있을 때만 `node scripts/recover-policy.mjs preview <사본.json> <정책.trial.json> <사전기록-SHA256>`으로 범위를 미리 보고, 확인 후 `apply`할 수 있습니다. 현재 검증된 정책 사본이 없어 실제 정책 복구는 미실행입니다. 비공개 메모 복원도 서버에 검증된 사본이 준비되고 B 계정이 확인되기 전에는 하지 않습니다.

저장점 전 확인은 `node --test test/r5.test.mjs test/stage12-operations.test.mjs test/stage12-checks.test.mjs`로 수행합니다. `src/attack-check.mjs`는 격리 실행을 위해 import 없이 두고, 각 GET 요청에 고유 `requestKey`와 `caseId`를 `alephEvidence` 메타데이터로 붙입니다(URL·헤더에는 ID를 넣지 않습니다). `observed`는 HTTP 상태, `bodyBytes`, `jsonArrayLength`, `jsonReady`, `method`, `urlSha256`만 포함하고 요청 ID·UTC 확인 시각은 별도 필드에 기록합니다. `npm run bundle`과 `GET /api/checks`는 같은 검사 함수를 씁니다. 번들은 `artifacts/submission.json` 하나만 쓰고, 작전실 점검 기록은 `/api/checks` 응답에서 실시간으로 제공합니다. 서버가 실제 배포 요청에서 만든 막음·뚫림·미실행 수치와 표를 화면에 그대로 표시하며, 점검 실패 시 0이나 성공으로 대체하지 않습니다. 요청을 보내지 않은 엔진·계정·복구 시험은 `not_run`으로 남깁니다. 이 자기 점검이 41종 총공세나 A/B 정상·금지 요청을 대신하지 않습니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 5단계부터는 쿼리·인증 정보가 없는 HTTPS `originalApiUrl`도 함께 기록합니다. 필수 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`은 이 저장소의 현재 공개 GitHub 주소와 Vercel 배포 주소를 가리킵니다. 학생은 실제 주소·원본 API·발급자 정보를 유지하고 서버 비밀값을 이 파일에 넣지 않습니다. `npm run bundle`은 완료된 변경을 커밋한 뒤 실제 배포의 공개 점검을 포함해 실행합니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 현재 `src/attack-check.mjs`는 실제 배포의 익명 `/api/notes` JSON 거부, 빈 `/data.json`, `/aleph.json`의 현재 단계 정보, 첫 화면 보안 헤더를 확인합니다. 이 점검은 A/B 계정의 소유자 접근 검사나 원본 Data API의 anon-key 접근을 수행하지 않습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽고 이번 요청의 단계만 바꿉니다. 데이터 보호·로그인·허용 경로·정책 변경은 제공된 계약을 따릅니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 브라우저, 로그, 작전실 표에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
