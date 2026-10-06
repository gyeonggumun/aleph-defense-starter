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
3. 배포된 `/data.json`의 `notes` 배열은 비어 있습니다.
4. GitHub 기본 브랜치의 `data.json`과 `public/data.json`을 열고, GitHub 코드 검색으로 가상 메모 제목과 본문을 각각 검색해 최신 파일에 남지 않았는지 확인합니다.
5. 이전 공개 커밋과 과거 Vercel 배포는 이 변경으로 삭제되거나 비공개 처리되지 않습니다. 과거 노출까지 해결됐다고 간주하지 마세요.

로컬 정적 확인은 `node scripts/build-public.mjs --local`로 합니다. 이 명령은 배포나 API 연결을 증명하지 않습니다. 제출 묶음은 2단계 저장점 커밋 뒤 `bundle-notes.json`에 실행한 점검 결과만 적고 `npm run bundle`을 실행합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.
