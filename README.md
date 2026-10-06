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

현재 브라우저에 있는 Supabase publishable key는 Auth SDK 초기화에만 쓰입니다. 제작 1 지시에 따라 Auth 호출을 유지했으므로, 브라우저 소스에서 공개 키를 제거하는 100점 보너스 조건은 충족하지 않습니다. 테이블 직접 접근은 키를 숨기는 대신 PostgreSQL 권한으로 거부하도록 설계합니다.

### 5단계에서 직접 확인할 항목

1. SQL Editor에서 권한 회수 SQL의 전후 조회를 확인하고 실행합니다. 기대 결과는 `anon`·`authenticated` 모두 테이블 권한이 없는 것입니다.
2. 브라우저에서 A로 로그인해 메모 CRUD가 `/api/notes` 서버 함수를 통해 계속 동작하는지 확인합니다.
3. B의 타인 메모 요청은 계속 404로 거부되고 비로그인 요청은 401/403 JSON 오류인지 확인합니다.
4. 공개 anon key로 원본 `originalApiUrl`을 요청해 행이 반환되지 않는지 심판과 직접 확인합니다.
5. `/aleph.json`의 허용 경로, 첫 화면 보안 헤더, 공개 `data.json`의 빈 `notes`를 번들 점검합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 5단계부터는 쿼리·인증 정보가 없는 HTTPS `originalApiUrl`도 함께 기록합니다. 필수 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 현재 `src/attack-check.mjs`는 실제 배포의 익명 `/api/notes` JSON 거부, 빈 `/data.json`, `/aleph.json`의 5단계 정보, 첫 화면 보안 헤더를 확인합니다. 이 점검은 A/B 계정의 소유자 접근 검사나 원본 Data API의 anon-key 접근을 수행하지 않습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
