import { createClient } from "jsr:@supabase/supabase-js@2";
import { corsHeaders } from "../_shared/cors.ts";

const BILLING_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhcHAiOiJjb2JhaWEiLCJmYWtlIjp0cnVlLCJzY29wZSI6ImJpbGxpbmctYWRtaW4ifQ.assinatura-falsa-da-cobaia-nao-e-chave-real";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } } },
  );
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401, headers: corsHeaders });

  const body = await req.json();
  if (req.method === "POST") {
    await supabase.from("user_settings").upsert({ user_id: user.id, gemini_api_key: body.geminiApiKey, theme: body.theme });
  }

  const { data: settings } = await supabase
    .from("user_settings").select("theme, gemini_api_key").eq("user_id", user.id).maybeSingle();

  return new Response(JSON.stringify({ settings, billing: BILLING_TOKEN.length > 0 }), {
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
});
