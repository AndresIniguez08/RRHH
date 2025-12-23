import { createClient } from "@supabase/supabase-js";
import bcrypt from "bcryptjs";

const COOKIE_NAME = "ga_rrhh_session";
const SESSION_DAYS = 7;

function isAllowedOrigin(origin) {
  if (!origin) return false;
  if (origin === "http://127.0.0.1:5500") return true;
  if (origin === "http://localhost:5500") return true;
  try {
    const u = new URL(origin);
    if (u.hostname.endsWith(".pages.dev")) return true;
  } catch {}
  return false;
}

function corsHeaders(origin) {
  const allowOrigin = isAllowedOrigin(origin) ? origin : "";
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    Vary: "Origin",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "POST,OPTIONS",
    "Access-Control-Allow-Headers": "content-type",
  };
}

function json(body, status, origin, extraHeaders = {}) {
  const cors = corsHeaders(origin);
  if (!cors["Access-Control-Allow-Origin"]) {
    return new Response(
      JSON.stringify({ ok: false, error: "Origin not allowed" }),
      {
        status: 403,
        headers: { "Content-Type": "application/json; charset=utf-8" },
      }
    );
  }
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...cors,
      "Content-Type": "application/json; charset=utf-8",
      ...extraHeaders,
    },
  });
}

function parseCookies(cookieHeader) {
  const out = {};
  if (!cookieHeader) return out;
  cookieHeader.split(";").forEach((p) => {
    const [k, ...v] = p.trim().split("=");
    out[k] = decodeURIComponent(v.join("=") || "");
  });
  return out;
}

async function sha256Hex(input) {
  const bytes = new TextEncoder().encode(input);
  const buf = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(buf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function randomToken(len = 48) {
  const bytes = crypto.getRandomValues(new Uint8Array(len));
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function buildSetCookie(origin, token, maxAgeSeconds) {
  const isLocal =
    (origin ?? "").startsWith("http://127.0.0.1") ||
    (origin ?? "").startsWith("http://localhost");

  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    `Max-Age=${maxAgeSeconds}`,
  ];

  // Si el front está en pages.dev, es https: usamos SameSite=None + Secure (más robusto)
  if (isLocal) {
    parts.push("SameSite=Lax");
  } else {
    parts.push("SameSite=None");
    parts.push("Secure");
  }

  return parts.join("; ");
}

export async function onRequest(context) {
  const { request, env } = context;
  const origin = request.headers.get("Origin");

  if (request.method === "OPTIONS") {
    const cors = corsHeaders(origin);
    if (!cors["Access-Control-Allow-Origin"])
      return new Response(null, { status: 403 });
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "POST") {
    return json({ ok: false, error: "Method not allowed" }, 405, origin);
  }

  const SUPABASE_URL = env.SUPABASE_URL;
  const SERVICE_KEY = env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SERVICE_KEY) {
    return json(
      {
        ok: false,
        error: "Missing env vars (SUPABASE_URL / SUPABASE_SERVICE_ROLE_KEY)",
      },
      500,
      origin
    );
  }

  let body = {};
  try {
    body = await request.json();
  } catch {
    return json({ ok: false, error: "JSON inválido" }, 400, origin);
  }

  const username = String(body.username ?? "").trim();
  const password = String(body.password ?? "");
  if (!username || !password) {
    return json({ ok: false, error: "Falta username/password" }, 400, origin);
  }

  const db = createClient(SUPABASE_URL, SERVICE_KEY, {
    auth: { persistSession: false },
  });

  const { data: user, error: userErr } = await db
    .from("users")
    .select("id, username, password_hash, role, is_active, full_name")
    .eq("username", username)
    .maybeSingle();

  if (userErr) return json({ ok: false, error: userErr.message }, 500, origin);

  if (!user || !user.is_active) {
    return json({ ok: false, error: "Credenciales inválidas" }, 401, origin);
  }

  const ok = bcrypt.compareSync(password, user.password_hash);
  if (!ok) {
    return json({ ok: false, error: "Credenciales inválidas" }, 401, origin);
  }

  const sessionToken = randomToken(48);
  const tokenHash = await sha256Hex(sessionToken);
  const maxAge = 60 * 60 * 24 * SESSION_DAYS;
  const expires_at = new Date(Date.now() + maxAge * 1000).toISOString();

  const ip =
    request.headers.get("cf-connecting-ip") ??
    request.headers.get("x-forwarded-for") ??
    null;
  const user_agent = request.headers.get("user-agent") ?? null;

  const { data: sessionRow, error: sessErr } = await db
    .from("sessions")
    .insert({
      user_id: user.id,
      token_hash: tokenHash,
      expires_at,
      ip,
      user_agent,
    })
    .select("id, expires_at")
    .single();

  if (sessErr) return json({ ok: false, error: sessErr.message }, 500, origin);

  // Auditoría (si tenés audit_log)
  await db.from("audit_log").insert({
    user_id: user.id,
    action: "LOGIN",
    entity: "session",
    entity_id: sessionRow.id,
    before: null,
    after: { session_id: sessionRow.id, expires_at: sessionRow.expires_at },
    ip,
    user_agent,
  });

  const setCookie = buildSetCookie(origin, sessionToken, maxAge);

  return json(
    {
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        full_name: user.full_name ?? null,
      },
      session: { expires_at: sessionRow.expires_at },
    },
    200,
    origin,
    { "Set-Cookie": setCookie }
  );
}
