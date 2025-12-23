const COOKIE_NAME = "ga_rrhh_session";

export function buildSessionCookie(value, { maxAgeSeconds } = {}) {
  // Cloudflare Pages siempre HTTPS en producción => Secure OK
  // SameSite=Lax suele ser correcto para apps normales (evita CSRF básica en varios casos)
  const parts = [
    `${COOKIE_NAME}=${encodeURIComponent(value)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Lax",
  ];
  if (typeof maxAgeSeconds === "number") parts.push(`Max-Age=${maxAgeSeconds}`);
  return parts.join("; ");
}

export function buildClearSessionCookie() {
  // Max-Age=0 + valor vacío
  return buildSessionCookie("", { maxAgeSeconds: 0 });
}

export const SESSION_COOKIE_NAME = COOKIE_NAME;
