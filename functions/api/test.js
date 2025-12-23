export async function onRequest({ request }) {
  return new Response(
    JSON.stringify({
      ok: true,
      message: "API funcionando en Cloudflare Pages",
      url: request.url,
      method: request.method,
    }),
    { headers: { "Content-Type": "application/json; charset=utf-8" } }
  );
}
