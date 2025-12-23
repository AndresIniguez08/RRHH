import { createClient } from "@supabase/supabase-js";

const COOKIE_NAME = "ga_rrhh_session";

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

function buildDeleteCookie(origin) {
  const isLocal =
    (origin ?? "").startsWith("http://127.0.0.1") ||
    (origin ?? "").startsWith("http://localhost");
  const parts = [`${COOKIE_NAME}=`, "Path=/", "HttpOnly", "Max-Age=0"];
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
    return json({ ok: false, error: "Missing env vars" }, 500, origin);
  }

  const cookies = parseCookies(request.headers.get("cookie"));
  const token = cookies[COOKIE_NAME];

  const delCookie = buildDeleteCookie(origin);
  const db = createClient(SUPABASE_URL, SERVICE_KEY, {
    auth: { persistSession: false },
  });

  if (token) {
    const tokenHash = await sha256Hex(token);

    const { data: sess } = await db
      .from("sessions")
      .select("id, user_id, revoked_at")
      .eq("token_hash", tokenHash)
      .maybeSingle();

    if (sess && !sess.revoked_at) {
      await db
        .from("sessions")
        .update({ revoked_at: new Date().toISOString() })
        .eq("id", sess.id);

      await db.from("audit_log").insert({
        user_id: sess.user_id,
        action: "LOGOUT",
        entity: "session",
        entity_id: sess.id,
        before: { session_id: sess.id },
        after: { revoked_at: new Date().toISOString() },
        ip: request.headers.get("cf-connecting-ip") ?? null,
        user_agent: request.headers.get("user-agent") ?? null,
      });
    }
  }

  return json({ ok: true }, 200, origin, { "Set-Cookie": delCookie });
}
