import { createClient } from "jsr:@supabase/supabase-js@2";
import { corsHeaders } from "../_shared/cors.ts";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } } },
  );
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401, headers: corsHeaders });

  const { url } = await req.json();
  const page = await fetch(url);
  const html = await page.text();
  const title = html.match(/<title>([^<]*)<\/title>/i)?.[1] ?? url;

  return new Response(JSON.stringify({ title, excerpt: html.slice(0, 2000) }), {
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
});
