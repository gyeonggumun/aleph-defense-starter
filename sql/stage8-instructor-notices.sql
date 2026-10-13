-- 학습용 강사 공지 자원. 기존 vault_notes와 다른 자원 ID를 사용합니다.
create table if not exists public.instructor_notices (
  id uuid primary key,
  title text not null check (char_length(title) between 1 and 200),
  content text not null check (char_length(content) between 1 and 5000),
  created_at timestamptz not null default now()
);

alter table public.instructor_notices enable row level security;
revoke all on table public.instructor_notices from public, anon, authenticated;
grant select, update on table public.instructor_notices to service_role;

insert into public.instructor_notices (id, title, content)
values ('23e19e6c-6223-4d86-a635-8c28a5e1e786', '학습용 강사 공지', '자료실 실습을 위한 가상 공지입니다.')
on conflict (id) do nothing;
