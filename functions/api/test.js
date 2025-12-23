import { createClient } from "@supabase/supabase-js";
import bcrypt from "bcryptjs";

/**
 * Router único para /api/*
 * Rutas:
 *  - GET  /api/test
 *  - POST /api/auth-login
 *  - GET  /api/auth-me
 *  - POST /api/auth-logout
 */

// Cambiá el nombre si querés, pero mantenelo igual en login/me/logout
const COOKIE_NAME = "ga_rrhh_session";

// Permitimos localhost + tu Pages domain
function isAllowedOrigin(origin) {
  if (!origin) return false;
  if (origin === "http://127.0.0.1:5500") return true;
  if (origin === "http://localhost:5500") return true;

  // Allow pages.dev (prod y previews)
  try {
    const u = new URL(origin);
    if (u.hostname.endsWith(".pages.dev")) return true;
  } catch {}
  return false;
}

function corsHeaders(origin) {
  // En requests con credentials NO puede ser '*'
  const allowOrigin = isAllowedOrigin(origin) ? origin : "";
  const h = {
    "Access-Control-Allow-Origin": allowOrigin,
    Vary: "Origin",
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET,POST,OPTIONS",
    "Access-Control-Allow-Headers":
      "content-type, authorization, apikey, x-client-info",
  };
  return h;
}

function json(body, status, origin, extraHeaders = {}) {
  const cors = corsHeaders(origin);
  // Si el origin no está permitido, cortamos (evita líos de CORS)
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
  cookieHeader.split(";").forEach((part) => {
    const [k, ...v] = part.trim().split("=");
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

  // Si querés que funcione cross-site (ej: localhost -> pages.dev), necesitás SameSite=None + Secure
  // En local NO podés usar Secure (http), entonces usamos Lax.
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    `Max-Age=${maxAgeSeconds}`,
  ];

  if (isLocal) {
    parts.push("SameSite=Lax");
  } else {
    parts.push("SameSite=None");
    parts.push("Secure");
  }

  return parts.join("; ");
}

function buildDeleteCookie(origin) {
  // Borramos cookie (Max-Age=0)
  return buildSetCookie(origin, "", 0);
}

function getDb(env) {
  const url = env.SUPABASE_URL;
  const serviceKey = env.SUPABASE_SERVICE_ROLE_KEY;

  if (!url || !serviceKey) {
    throw new Error(
      "Missing SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in Cloudflare env"
    );
  }

  return createClient(url, serviceKey, { auth: { persistSession: false } });
}

export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const origin = request.headers.get("Origin");

  // Preflight
  if (request.method === "OPTIONS") {
    const cors = corsHeaders(origin);
    if (!cors["Access-Control-Allow-Origin"])
      return new Response(null, { status: 403 });
    return new Response(null, { status: 204, headers: cors });
  }

  // Normalizamos path: /api/xxx
  const path = url.pathname;

  // --- GET /api/test
  if (request.method === "GET" && path === "/api/test") {
    return json(
      {
        ok: true,
        message: "API funcionando en Cloudflare Pages",
        url: url.toString(),
        method: "GET",
      },
      200,
      origin
    );
  }

  // --- POST /api/auth-login
  if (request.method === "POST" && path === "/api/auth-login") {
    try {
      const db = getDb(env);

      let body = {};
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "JSON inválido" }, 400, origin);
      }

      const username = String(body.username ?? "").trim();
      const password = String(body.password ?? "");

      if (!username || !password) {
        return json(
          { ok: false, error: "Falta username/password" },
          400,
          origin
        );
      }

      const { data: user, error: userErr } = await db
        .from("users")
        .select("id, username, password_hash, role, is_active, full_name")
        .eq("username", username)
        .maybeSingle();

      if (userErr)
        return json({ ok: false, error: userErr.message }, 500, origin);

      if (!user || !user.is_active) {
        return json(
          { ok: false, error: "Credenciales inválidas" },
          401,
          origin
        );
      }

      const ok = bcrypt.compareSync(password, user.password_hash);
      if (!ok) {
        return json(
          { ok: false, error: "Credenciales inválidas" },
          401,
          origin
        );
      }

      // Crear sesión
      const session_token = randomToken(48); // va a cookie
      const token_hash = await sha256Hex(session_token); // guardado DB
      const expires_at = new Date(
        Date.now() + 1000 * 60 * 60 * 24 * 7
      ).toISOString(); // 7 días

      const ip =
        request.headers.get("cf-connecting-ip") ??
        request.headers.get("x-forwarded-for") ??
        null;
      const user_agent = request.headers.get("user-agent") ?? null;

      const { data: sessionRow, error: sessErr } = await db
        .from("sessions")
        .insert({
          user_id: user.id,
          token_hash,
          expires_at,
          ip,
          user_agent,
        })
        .select("id, expires_at")
        .single();

      if (sessErr)
        return json({ ok: false, error: sessErr.message }, 500, origin);

      // Auditoría (opcional)
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

      const setCookie = buildSetCookie(origin, session_token, 60 * 60 * 24 * 7);

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
    } catch (e) {
      console.error("AUTH_LOGIN_ERROR", e);
      return json(
        { ok: false, error: "Unhandled", detail: String(e) },
        500,
        origin
      );
    }
  }

  // --- GET /api/auth-me
  if (request.method === "GET" && path === "/api/auth-me") {
    try {
      const db = getDb(env);

      const cookies = parseCookies(request.headers.get("cookie"));
      const token = cookies[COOKIE_NAME];

      if (!token) {
        return json({ ok: false, error: "No session" }, 401, origin);
      }

      const token_hash = await sha256Hex(token);

      const { data, error } = await db
        .from("sessions")
        .select(
          "id, expires_at, revoked_at, users:user_id ( id, username, role, full_name, is_active )"
        )
        .eq("token_hash", token_hash)
        .maybeSingle();

      if (error) return json({ ok: false, error: error.message }, 500, origin);

      if (!data || data.revoked_at) {
        return json({ ok: false, error: "Session invalid" }, 401, origin);
      }

      if (new Date(data.expires_at).getTime() <= Date.now()) {
        return json({ ok: false, error: "Session expired" }, 401, origin);
      }

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
    } catch (e) {
      console.error("AUTH_ME_ERROR", e);
      return json(
        { ok: false, error: "Unhandled", detail: String(e) },
        500,
        origin
      );
    }
  }

  // --- POST /api/auth-logout
  if (request.method === "POST" && path === "/api/auth-logout") {
    try {
      const db = getDb(env);

      const cookies = parseCookies(request.headers.get("cookie"));
      const token = cookies[COOKIE_NAME];

      // Siempre borramos cookie igual (aunque no exista)
      const delCookie = buildDeleteCookie(origin);

      if (!token) {
        return json({ ok: true, message: "No session" }, 200, origin, {
          "Set-Cookie": delCookie,
        });
      }

      const token_hash = await sha256Hex(token);

      const { data: sess, error: sessErr } = await db
        .from("sessions")
        .select("id, user_id, revoked_at")
        .eq("token_hash", token_hash)
        .maybeSingle();

      if (sessErr)
        return json({ ok: false, error: sessErr.message }, 500, origin);

      if (sess && !sess.revoked_at) {
        await db
          .from("sessions")
          .update({ revoked_at: new Date().toISOString() })
          .eq("id", sess.id);

        // Auditoría (opcional)
        const ip =
          request.headers.get("cf-connecting-ip") ??
          request.headers.get("x-forwarded-for") ??
          null;
        const user_agent = request.headers.get("user-agent") ?? null;

        await db.from("audit_log").insert({
          user_id: sess.user_id,
          action: "LOGOUT",
          entity: "session",
          entity_id: sess.id,
          before: { session_id: sess.id },
          after: { revoked_at: new Date().toISOString() },
          ip,
          user_agent,
        });
      }

      return json({ ok: true }, 200, origin, { "Set-Cookie": delCookie });
    } catch (e) {
      console.error("AUTH_LOGOUT_ERROR", e);
      return json(
        { ok: false, error: "Unhandled", detail: String(e) },
        500,
        origin
      );
    }
  }

  // 404
  return json({ ok: false, error: "Not found", path }, 404, origin);
}
