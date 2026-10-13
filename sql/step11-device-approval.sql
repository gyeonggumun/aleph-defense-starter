-- Device credentials are private server-side records. Registration is pending
-- until an administrator changes one verified credential to approved.
create table if not exists public.device_credentials (
  credential_id text primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  public_key text not null,
  counter bigint not null default 0,
  transports jsonb not null default '[]'::jsonb,
  status text not null default 'pending' check (status in ('pending','approved','revoked')),
  created_at timestamptz not null default now()
);
create index if not exists device_credentials_owner_idx
  on public.device_credentials (owner_id, status);
alter table public.device_credentials enable row level security;
revoke all on table public.device_credentials from public, anon, authenticated;
grant select, insert, update, delete on table public.device_credentials to service_role;

create table if not exists public.device_challenges (
  id uuid primary key,
  owner_id uuid not null references auth.users(id) on delete cascade,
  flow text not null check (flow in ('registration','authentication')),
  challenge text not null,
  expires_at timestamptz not null,
  used_at timestamptz
);
create index if not exists device_challenges_owner_idx
  on public.device_challenges (owner_id, expires_at);
alter table public.device_challenges enable row level security;
revoke all on table public.device_challenges from public, anon, authenticated;
grant select, insert, update, delete on table public.device_challenges to service_role;
