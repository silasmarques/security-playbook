const STATUS_URL = "https://status.supabase.com/api/v2/status.json";

Deno.serve(async () => {
  let upstream = "unknown";
  try {
    const res = await fetch(STATUS_URL, { signal: AbortSignal.timeout(3000) });
    upstream = res.ok ? "ok" : "degraded";
  } catch (error) {
    console.error(JSON.stringify({ level: "warn", event: "health.upstream_failed", name: (error as Error).name }));
  }
  return new Response(JSON.stringify({ status: "ok", upstream }), {
    headers: {
      "Content-Type": "application/json",
      // playbook-ignore: C-CORS-WILDCARD endpoint público de status, sem autenticação e sem dado de usuário
      "Access-Control-Allow-Origin": "*",
    },
  });
});
