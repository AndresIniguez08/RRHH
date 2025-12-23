import { createClient } from "https://esm.sh/@supabase/supabase-js@2";
import bcrypt from "https://esm.sh/bcryptjs@2.4.3";

export async function onRequestPost({ request, env }) {
  const origin = request.headers.get("Origin");

  // CORS correcto para cookies
  const corsHeaders = {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Headers": "content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    Vary: "Origin",
  };

  if (request.method === "OPTIONS") {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const body = await request.json();
    const { username, password } = body;

    if (!username || !password) {
      return new Response(
        JSON.stringify({ ok: false, error: "Faltan credenciales" }),
        { status: 400, headers: corsHeaders }
      );
    }

    const supabase = createClient(
      env.SUPABASE_URL,
      env.SUPABASE_SERVICE_ROLE_KEY
    );

    const { data: user } = await supabase
      .from("users")
      .select("id, username, password_hash, role, full_name, is_active")
      .eq("username", username)
      .single();

    if (!user || !user.is_active) {
      return new Response(
        JSON.stringify({ ok: false, error: "Credenciales inválidas" }),
        { status: 401, headers: corsHeaders }
      );
    }

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) {
      return new Response(
        JSON.stringify({ ok: false, error: "Credenciales inválidas" }),
        { status: 401, headers: corsHeaders }
      );
    }

    // token simple (después lo endurecemos)
    const token = crypto.randomUUID();
    const expires = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000);

    await supabase.from("sessions").insert({
      user_id: user.id,
      token,
      expires_at: expires.toISOString(),
    });

    const cookie = [
      `rrhh_session=${token}`,
      "HttpOnly",
      "Path=/",
      "SameSite=Lax",
      "Max-Age=604800",
      "Secure",
    ].join("; ");

    return new Response(
      JSON.stringify({
        ok: true,
        user: {
          id: user.id,
          username: user.username,
          role: user.role,
          full_name: user.full_name,
        },
      }),
      {
        status: 200,
        headers: {
          ...corsHeaders,
          "Set-Cookie": cookie,
          "Content-Type": "application/json",
        },
      }
    );
  } catch (err) {
    return new Response(JSON.stringify({ ok: false, error: "Server error" }), {
      status: 500,
      headers: corsHeaders,
    });
  }
}
