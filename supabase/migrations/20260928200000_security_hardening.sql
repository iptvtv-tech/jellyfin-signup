-- Security hardening (28 Sep 2026) — run once in the Supabase SQL Editor.

-- 1. Retire guessable invite codes (keeps their history, just stops new uses)
update public.jellyfin_invites set expires_at = now()
 where code in ('JELLYFISH-123', 'SOME-CODE', 'JELLYFISH-TEST');

-- 2. Failed-attempt log used to rate-limit invite guessing and reset spam.
--    Only a hash of the visitor's IP address is stored, and rows are cleared after a day.
create table if not exists public.jellyfin_attempts (
  id          bigint generated always as identity primary key,
  ip_hash     text not null,
  action      text not null,          -- 'bad-invite' | 'reset-request'
  created_at  timestamptz not null default now()
);
create index if not exists jellyfin_attempts_lookup on public.jellyfin_attempts (action, ip_hash, created_at);
alter table public.jellyfin_attempts enable row level security;
revoke all on public.jellyfin_attempts from anon, authenticated;
