-- Jellyfin invite signups + password reset
-- Run this whole file once in the Supabase SQL Editor.

-- Invite codes you hand out
create table if not exists public.jellyfin_invites (
  code        text primary key,
  note        text,                                  -- who it's for, e.g. "Sarah"
  max_uses    int  not null default 1 check (max_uses > 0),
  used_count  int  not null default 0 check (used_count >= 0),
  expires_at  timestamptz,                            -- null = never expires
  created_at  timestamptz not null default now()
);

-- One row per Jellyfin account created through the signup page.
-- Passwords are NOT stored here; Jellyfin stores and hashes them.
create table if not exists public.jellyfin_accounts (
  id               bigint generated always as identity primary key,
  username         text not null unique,
  email            text not null,
  jellyfin_user_id text not null unique,
  invite_code      text references public.jellyfin_invites(code),
  created_at       timestamptz not null default now()
);
create index if not exists jellyfin_accounts_email_idx on public.jellyfin_accounts (lower(email));

-- Password reset tokens (only a SHA-256 hash of the token is stored)
create table if not exists public.jellyfin_reset_tokens (
  id          bigint generated always as identity primary key,
  account_id  bigint not null references public.jellyfin_accounts(id) on delete cascade,
  token_hash  text not null unique,
  expires_at  timestamptz not null,
  used_at     timestamptz,
  created_at  timestamptz not null default now()
);

-- Failure log, handy when something goes wrong
create table if not exists public.jellyfin_errors (
  id          bigint generated always as identity primary key,
  action      text not null,
  username    text,
  detail      text,
  created_at  timestamptz not null default now()
);

-- Lock everything down: no access from the browser at all.
-- Only the Edge Function (service role) touches these tables.
alter table public.jellyfin_invites      enable row level security;
alter table public.jellyfin_accounts     enable row level security;
alter table public.jellyfin_reset_tokens enable row level security;
alter table public.jellyfin_errors       enable row level security;
revoke all on public.jellyfin_invites, public.jellyfin_accounts,
              public.jellyfin_reset_tokens, public.jellyfin_errors
  from anon, authenticated;

-- Atomically claim one use of an invite. Returns true if the code was valid.
create or replace function public.claim_jellyfin_invite(p_code text)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  claimed int;
begin
  update jellyfin_invites
     set used_count = used_count + 1
   where code = p_code
     and used_count < max_uses
     and (expires_at is null or expires_at > now());
  get diagnostics claimed = row_count;
  return claimed = 1;
end;
$$;

-- Give a use back if the Jellyfin account couldn't be created.
create or replace function public.release_jellyfin_invite(p_code text)
returns void
language sql
security definer
set search_path = public
as $$
  update jellyfin_invites
     set used_count = greatest(used_count - 1, 0)
   where code = p_code;
$$;

revoke all on function public.claim_jellyfin_invite(text)   from public, anon, authenticated;
revoke all on function public.release_jellyfin_invite(text) from public, anon, authenticated;
grant execute on function public.claim_jellyfin_invite(text)   to service_role;
grant execute on function public.release_jellyfin_invite(text) to service_role;

-- ─── Creating invites ───────────────────────────────────────────────
-- One person, valid for 7 days:
--   insert into public.jellyfin_invites (code, note, max_uses, expires_at)
--   values ('MOVIE-NIGHT-7Q2K', 'for Sarah', 1, now() + interval '7 days');
--
-- A family code, 5 uses, never expires:
--   insert into public.jellyfin_invites (code, note, max_uses)
--   values ('FAMILY-2026', 'family', 5);
