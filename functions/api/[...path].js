export async function onRequest(context) {
  const { request, params } = context;

  return new Response(
    JSON.stringify({
      ok: true,
      message: "Cloudflare Pages Functions funcionando",
      path: params.path || [],
      url: request.url,
    }),
    {
      headers: {
        "Content-Type": "application/json",
      },
    }
  );
}
