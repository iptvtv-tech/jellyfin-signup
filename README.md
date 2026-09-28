# Jellyfin signup & password reset (Supabase)

This lets people create their own Jellyfin account on your seedhost server with an invite code you give them. They can also reset a forgotten password by email. Nothing gets installed on seedhost.

```
Account page (GitHub Pages) ──► Supabase Edge Function ──► Jellyfin API (seedhost)
                                        │
                                        ├── Supabase tables: invites, accounts, reset links
                                        └── Brevo: sends the reset emails
```

Jellyfin stores the passwords. Supabase only keeps the username, email and invite used.

| File | What it is |
|---|---|
| `supabase/migrations/…_jellyfin_invites.sql` | Tables and functions. Run once. |
| `supabase/functions/jellyfin-account/index.ts` | The Edge Function |
| `web/index.html` | The sign-up / forgot / reset page |

---

## 1. Jellyfin: get an API key and your server URL

1. Go to **Dashboard → API Keys → +**, name it `supabase-signup`, and copy the key.
2. Note your public Jellyfin address, e.g. `https://yourname.seedhost.eu/jellyfin`. You'll need it without a trailing slash.
3. *(Optional)* To limit which libraries new users can see, you need each library's ID. Open the library in the Jellyfin web app and copy the value after `topParentId=` or `parentId=` in the address bar. If you skip this, new users get every library.
4. Uninstall the **LDAP-Auth** plugin. It isn't needed.

## 2. Brevo: sender and API key (for reset emails)

1. In **Senders, Domains & Dedicated IPs → Senders**, make sure the address you'll send from is verified.
2. In **SMTP & API → API Keys**, create a key.

## 3. Supabase: database

Go to **SQL Editor → New query**, paste the whole `.sql` file, and click **Run**.

## 4. Supabase: the Edge Function

**Using the dashboard (no install needed)**

1. Go to **Edge Functions → Deploy a new function → Via Editor**.
2. Name it exactly `jellyfin-account`.
3. Paste in `index.ts` and deploy.
4. Open the function's **Details/Settings** and turn **Enforce JWT verification OFF**. The page calls the function without a Supabase login; the invite code and the emailed link are the protection.
5. Go to **Edge Functions → Secrets** and add:

| Secret | Example |
|---|---|
| `JELLYFIN_URL` | `https://yourname.seedhost.eu/jellyfin` |
| `JELLYFIN_API_KEY` | *(from step 1)* |
| `JELLYFIN_LIBRARY_IDS` | *(optional)* `f137a2dd21bbc1b99aa5c0f6bf02a805,a656b907eb3a73532e40e44b968d0225` |
| `BREVO_API_KEY` | *(from step 2)* |
| `MAIL_FROM` | your verified Brevo sender address |
| `MAIL_FROM_NAME` | `TC Media` *(or anything you like)* |
| `PAGE_URL` | where the page will live, e.g. `https://yourname.github.io/jellyfin-join/` |
| `ALLOWED_ORIGIN` | the page's site only, e.g. `https://yourname.github.io` |

**Or with the Supabase CLI**

```bash
supabase link --project-ref YOUR-PROJECT-REF
supabase db push
supabase functions deploy jellyfin-account --no-verify-jwt
supabase secrets set JELLYFIN_URL=... JELLYFIN_API_KEY=... BREVO_API_KEY=... MAIL_FROM=... PAGE_URL=... ALLOWED_ORIGIN=...
```

The function URL is `https://YOUR-PROJECT-REF.supabase.co/functions/v1/jellyfin-account`.

## 5. The page

1. In `web/index.html`, set `FUNCTION_URL` near the bottom to the URL above.
2. Put it on GitHub Pages, e.g. a new repo `jellyfin-join` with `index.html` at its root, then go to **Settings → Pages → Deploy from branch**.
3. Make sure `PAGE_URL` (step 4) matches the final address exactly, including the trailing `/`.

The page has `noindex`, so search engines won't list it.

## 6. Hand out invites

In the SQL Editor:

```sql
-- one person, valid for a week
insert into jellyfin_invites (code, note, max_uses, expires_at)
values ('MOVIE-NIGHT-7Q2K', 'Sarah', 1, now() + interval '7 days');

-- a family code good for 5 accounts
insert into jellyfin_invites (code, note, max_uses) values ('FAMILY-2026', 'family', 5);
```

Send them the page link and their code. You can also add rows in **Table Editor → jellyfin_invites**.

## Useful checks

```sql
select username, email, created_at from jellyfin_accounts order by created_at desc;  -- who signed up
select * from jellyfin_errors order by created_at desc limit 20;                    -- what went wrong
update jellyfin_invites set max_uses = used_count where code = 'FAMILY-2026';      -- kill a code
```

## How it behaves

**Signup**
- The invite code is claimed first, and no more than `max_uses` times.
- If anything fails afterwards, the use is given back and any half-made Jellyfin user is deleted.
- New users are not admins, can't delete media, and are hidden from the login-screen user list.

**Reset**
- The link is emailed to the address given at signup, works once, and expires after 30 minutes.
- Each account can request at most 3 links per hour.
- The page always shows the same message, so nobody can use it to find out which usernames or emails exist.

**Other limits**
- Accounts you created by hand in Jellyfin can't use reset, because the system has no email for them. Add a row to `jellyfin_accounts` with their username, email and Jellyfin user ID (shown in the address bar on their user page in the Dashboard) to enable it.
- Jellyfin's built-in "Forgot password" button still writes a PIN file on the server, which isn't useful on seedhost. Point people to this page instead.
