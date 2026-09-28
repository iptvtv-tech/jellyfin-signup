// Supabase Edge Function: Jellyfin signup (invite code) + password reset by email.
//
// POST JSON with an "action":
//   { action: "signup",        username, email, password, invite }
//   { action: "request-reset", login }            // username or email
//   { action: "reset",         token, password }
//
// Secrets (supabase secrets set KEY=value):
//   JELLYFIN_URL          e.g. https://yourname.seedhost.eu/jellyfin  (no trailing slash)
//   JELLYFIN_API_KEY      Jellyfin → Dashboard → API Keys (full admin rights: keep secret)
//   JELLYFIN_LIBRARY_IDS  optional, comma-separated library IDs new users can see (unset = all)
//   BREVO_API_KEY         Brevo → SMTP & API → API Keys
//   MAIL_FROM             a sender address verified in Brevo, e.g. media@yourdomain.com
//   MAIL_FROM_NAME        optional, default "Media Server"
//   PAGE_URL              where the account page lives, e.g. https://you.github.io/jellyfin-join/
//   ALLOWED_ORIGIN        optional, e.g. https://you.github.io (default "*")
// SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are provided automatically.

import { createClient } from "npm:@supabase/supabase-js@2";

const env = (k: string, d = "") => Deno.env.get(k) ?? d;
const JELLYFIN_URL = env("JELLYFIN_URL").replace(/\/+$/, "");
const JELLYFIN_API_KEY = env("JELLYFIN_API_KEY");
const LIBRARY_IDS = env("JELLYFIN_LIBRARY_IDS").split(",").map((s) => s.trim()).filter(Boolean);
const BREVO_API_KEY = env("BREVO_API_KEY");
const MAIL_FROM = env("MAIL_FROM");
const MAIL_FROM_NAME = env("MAIL_FROM_NAME", "Media Server");
const PAGE_URL = env("PAGE_URL");
const ALLOWED_ORIGIN = env("ALLOWED_ORIGIN", "*");

const RESET_TTL_MINUTES = 30;
const MAX_RESETS_PER_HOUR = 3;

const db = createClient(env("SUPABASE_URL"), env("SUPABASE_SERVICE_ROLE_KEY"), {
  auth: { persistSession: false },
});

const cors = {
  "Access-Control-Allow-Origin": ALLOWED_ORIGIN,
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "content-type, authorization, apikey, x-client-info",
};

const reply = (status: number, body: Record<string, unknown>) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { ...cors, "Content-Type": "application/json" },
  });

const jf = (path: string, init: RequestInit = {}) =>
  fetch(`${JELLYFIN_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "Authorization": `MediaBrowser Token="${JELLYFIN_API_KEY}"`,
      ...(init.headers ?? {}),
    },
  });

const logError = (action: string, username: string | null, detail: string) =>
  db.from("jellyfin_errors").insert({ action, username, detail });

const USERNAME_RE = /^[A-Za-z0-9._-]{3,32}$/;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const passwordOk = (p: string) => p.length >= 8 && p.length <= 128;

async function sha256(text: string) {
  const buf = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function randomToken() {
  const bytes = crypto.getRandomValues(new Uint8Array(32));
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const escapeHtml = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]!));

async function sendEmail(to: string, subject: string, html: string) {
  const res = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": BREVO_API_KEY, "Content-Type": "application/json", "Accept": "application/json" },
    body: JSON.stringify({
      sender: { email: MAIL_FROM, name: MAIL_FROM_NAME },
      to: [{ email: to }],
      subject,
      htmlContent: html,
    }),
  });
  if (!res.ok) throw new Error(`Brevo ${res.status}: ${await res.text()}`);
}

// ─── signup ─────────────────────────────────────────────────────────
async function signup(body: Record<string, string>) {
  const username = (body.username ?? "").trim();
  const email = (body.email ?? "").trim().toLowerCase();
  const password = body.password ?? "";
  const invite = (body.invite ?? "").trim();

  if (!USERNAME_RE.test(username)) {
    return reply(400, { error: "Username must be 3–32 characters: letters, numbers, dot, dash or underscore." });
  }
  if (!EMAIL_RE.test(email)) return reply(400, { error: "Please enter a valid email address." });
  if (!passwordOk(password)) return reply(400, { error: "Password must be at least 8 characters." });
  if (!invite) return reply(400, { error: "An invite code is required." });

  const { data: claimed, error: claimErr } = await db.rpc("claim_jellyfin_invite", { p_code: invite });
  if (claimErr) {
    await logError("signup", username, `claim: ${claimErr.message}`);
    return reply(500, { error: "Something went wrong. Please try again." });
  }
  if (!claimed) return reply(403, { error: "That invite code is invalid, used up or expired." });

  const fail = async (status: number, message: string, detail?: string) => {
    await db.rpc("release_jellyfin_invite", { p_code: invite });
    if (detail) await logError("signup", username, detail);
    return reply(status, { error: message });
  };

  // Username free?
  try {
    const usersRes = await jf("/Users");
    if (!usersRes.ok) return await fail(502, "Couldn't reach the media server.", `GET /Users ${usersRes.status}`);
    const users: Array<{ Name: string }> = await usersRes.json();
    if (users.some((u) => u.Name.toLowerCase() === username.toLowerCase())) {
      return await fail(409, "That username is already taken.");
    }
  } catch (e) {
    return await fail(502, "Couldn't reach the media server.", String(e));
  }

  // Create user (Jellyfin hashes the password)
  const createRes = await jf("/Users/New", {
    method: "POST",
    body: JSON.stringify({ Name: username, Password: password }),
  });
  if (!createRes.ok) {
    return await fail(502, "Couldn't create the account.", `POST /Users/New ${createRes.status}: ${await createRes.text()}`);
  }
  const user: { Id: string; Policy: Record<string, unknown> } = await createRes.json();

  const rollback = async (message: string, detail: string) => {
    await jf(`/Users/${user.Id}`, { method: "DELETE" });
    return await fail(502, message, detail);
  };

  // Permissions
  const policyRes = await jf(`/Users/${user.Id}/Policy`, {
    method: "POST",
    body: JSON.stringify({
      ...user.Policy,
      IsAdministrator: false,
      IsHidden: true,
      EnableRemoteAccess: true,
      EnableContentDeletion: false,
      EnableAllFolders: LIBRARY_IDS.length === 0,
      EnabledFolders: LIBRARY_IDS,
    }),
  });
  if (!policyRes.ok) {
    return await rollback("Couldn't finish setting up the account.", `Policy ${policyRes.status}: ${await policyRes.text()}`);
  }

  const { error: insErr } = await db.from("jellyfin_accounts").insert({
    username,
    email,
    jellyfin_user_id: user.Id,
    invite_code: invite,
  });
  if (insErr) return await rollback("Couldn't finish setting up the account.", `accounts insert: ${insErr.message}`);

  return reply(200, { ok: true, username, server: JELLYFIN_URL });
}

// ─── request-reset ──────────────────────────────────────────────────
async function requestReset(body: Record<string, string>) {
  const login = (body.login ?? "").trim();
  // Always the same answer, so the page can't be used to discover accounts.
  const generic = reply(200, {
    ok: true,
    message: "If that account exists, a reset link has been sent to its email address.",
  });
  if (!login) return reply(400, { error: "Enter your username or email." });

  const q = db.from("jellyfin_accounts").select("id, username, email");
  const { data: accounts } = login.includes("@")
    ? await q.ilike("email", login)
    : await q.ilike("username", login);
  if (!accounts?.length) return generic;

  for (const acct of accounts) {
    const since = new Date(Date.now() - 60 * 60 * 1000).toISOString();
    const { count } = await db
      .from("jellyfin_reset_tokens")
      .select("id", { count: "exact", head: true })
      .eq("account_id", acct.id)
      .gte("created_at", since);
    if ((count ?? 0) >= MAX_RESETS_PER_HOUR) continue;

    const token = randomToken();
    await db.from("jellyfin_reset_tokens").insert({
      account_id: acct.id,
      token_hash: await sha256(token),
      expires_at: new Date(Date.now() + RESET_TTL_MINUTES * 60 * 1000).toISOString(),
    });

    const link = `${PAGE_URL}${PAGE_URL.includes("?") ? "&" : "?"}reset=${token}`;
    try {
      await sendEmail(
        acct.email,
        "Reset your media server password",
        `<p>Hi ${escapeHtml(acct.username)},</p>
         <p>Someone asked to reset the password for your media server account.
            Click below to choose a new one. The link works once and expires in ${RESET_TTL_MINUTES} minutes.</p>
         <p><a href="${link}" style="display:inline-block;padding:10px 18px;background:#00a4dc;color:#fff;border-radius:6px;text-decoration:none">Choose a new password</a></p>
         <p>If you didn't ask for this, you can ignore this email; your password hasn't changed.</p>`,
      );
    } catch (e) {
      await logError("request-reset", acct.username, String(e));
    }
  }
  return generic;
}

// ─── reset ──────────────────────────────────────────────────────────
async function reset(body: Record<string, string>) {
  const token = (body.token ?? "").trim();
  const password = body.password ?? "";
  if (!/^[0-9a-f]{64}$/.test(token)) return reply(400, { error: "This reset link is invalid." });
  if (!passwordOk(password)) return reply(400, { error: "Password must be at least 8 characters." });

  const { data: row } = await db
    .from("jellyfin_reset_tokens")
    .select("id, account_id, expires_at, used_at, jellyfin_accounts(username, jellyfin_user_id)")
    .eq("token_hash", await sha256(token))
    .maybeSingle();

  if (!row || row.used_at || new Date(row.expires_at) < new Date()) {
    return reply(400, { error: "This reset link is invalid or has expired. Please request a new one." });
  }

  // Mark used first, only if still unused (stops the same link working twice)
  const { data: marked } = await db
    .from("jellyfin_reset_tokens")
    .update({ used_at: new Date().toISOString() })
    .eq("id", row.id)
    .is("used_at", null)
    .select("id");
  if (!marked?.length) return reply(400, { error: "This reset link has already been used." });

  // deno-lint-ignore no-explicit-any
  const acct = row.jellyfin_accounts as any;
  const res = await jf(`/Users/${acct.jellyfin_user_id}/Password`, {
    method: "POST",
    body: JSON.stringify({ NewPw: password, ResetPassword: false }),
  });
  if (!res.ok) {
    await db.from("jellyfin_reset_tokens").update({ used_at: null }).eq("id", row.id);
    await logError("reset", acct.username, `Password ${res.status}: ${await res.text()}`);
    return reply(502, { error: "Couldn't change the password right now. Please try again." });
  }

  // Invalidate any other outstanding links for this account
  await db
    .from("jellyfin_reset_tokens")
    .update({ used_at: new Date().toISOString() })
    .eq("account_id", row.account_id)
    .is("used_at", null);

  return reply(200, { ok: true, username: acct.username, server: JELLYFIN_URL });
}

// ─── router ─────────────────────────────────────────────────────────
Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return reply(405, { error: "Method not allowed" });
  if (!JELLYFIN_URL || !JELLYFIN_API_KEY) return reply(500, { error: "Server is not configured yet." });

  let body: Record<string, string>;
  try {
    body = await req.json();
  } catch {
    return reply(400, { error: "Invalid request." });
  }

  try {
    switch (body.action) {
      case "signup":
        return await signup(body);
      case "request-reset":
        if (!BREVO_API_KEY || !MAIL_FROM || !PAGE_URL) {
          return reply(500, { error: "Password reset isn't set up yet." });
        }
        return await requestReset(body);
      case "reset":
        return await reset(body);
      default:
        return reply(400, { error: "Unknown action." });
    }
  } catch (e) {
    await logError(String(body.action), body.username ?? null, String(e));
    return reply(500, { error: "Something went wrong. Please try again." });
  }
});
