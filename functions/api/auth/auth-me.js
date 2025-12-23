import { createClient } from "@supabase/supabase-js";

const COOKIE_NAME = "ga_rrhh_session";

function isAllowedOrigin(origin) {
  // Si no hay Origin, no es una request CORS típica (mismo sitio o herramientas).
  // La dejamos pasar.
  if (!origin) return true;

  if (origin === "http://127.0.0.1:5500") return true;
  if (origin === "http://localhost:5500") return true;

  try {
    const u = new URL(origin);
    if (u.hostname.endsWith(".pages.dev")) return true;
  } catch {}

  return false;
}

function corsHeaders(origin) {
  // Sin Origin: no es CORS -> no hace falta Access-Control-Allow-Origin
  if (!origin) {
    return {
      Vary: "Origin",
    };
  }

  const allowOrigin = isAllowedOrigin(origin) ? origin : "";
  return {
    "Access-Control-Allow-Origin": allowOrigin,
    Vary: "Origin",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,OPTIONS",
    "Access-Control-Allow-Headers": "content-type",
  };
}

function json(body, status, origin, extraHeaders = {}) {
  if (origin && !isAllowedOrigin(origin)) {
    return new Response(
      JSON.stringify({ ok: false, error: "Origin not allowed" }),
      {
        status: 403,
        headers: { "Content-Type": "application/json; charset=utf-8" },
      }
    );
  }
  const cors = corsHeaders(origin);
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...cors,
      ...(origin ? { "Access-Control-Allow-Credentials": "true" } : {}),
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

export async function onRequest(context) {
  const { request, env } = context;
  const origin = request.headers.get("Origin");

  if (request.method === "OPTIONS") {
    const cors = corsHeaders(origin);
    if (!cors["Access-Control-Allow-Origin"])
      return new Response(null, { status: 403 });
    return new Response(null, { status: 204, headers: cors });
  }

  if (request.method !== "GET") {
    return json({ ok: false, error: "Method not allowed" }, 405, origin);
  }

  const SUPABASE_URL = env.SUPABASE_URL;
  const SERVICE_KEY = env.SUPABASE_SERVICE_ROLE_KEY;
  if (!SUPABASE_URL || !SERVICE_KEY) {
    return json({ ok: false, error: "Missing env vars" }, 500, origin);
  }

  const cookies = parseCookies(request.headers.get("cookie"));
  const token = cookies[COOKIE_NAME];
  if (!token) return json({ ok: false, error: "No session" }, 401, origin);

  const tokenHash = await sha256Hex(token);
  const db = createClient(SUPABASE_URL, SERVICE_KEY, {
    auth: { persistSession: false },
  });

  const { data, error } = await db
    .from("sessions")
    .select(
      "id, expires_at, revoked_at, users:user_id ( id, username, role, full_name, is_active )"
    )
    .eq("token_hash", tokenHash)
    .maybeSingle();

  if (error) return json({ ok: false, error: error.message }, 500, origin);

  if (!data || data.revoked_at)
    return json({ ok: false, error: "Session invalid" }, 401, origin);
  if (new Date(data.expires_at).getTime() <= Date.now())
    return json({ ok: false, error: "Session expired" }, 401, origin);

  const u = data.users;
  if (!u || !u.is_active)
    return json({ ok: false, error: "User inactive" }, 401, origin);

  return json(
    {
      ok: true,
      user: {
        id: u.id,
        username: u.username,
        role: u.role,
        full_name: u.full_name ?? null,
      },
      session: { expires_at: data.expires_at },
    },
    200,
    origin
  );
}
