import { createClient } from "jsr:@supabase/supabase-js@2";
import { corsHeaders } from "../_shared/cors.ts";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } } },
  );
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401, headers: corsHeaders });

  const { data: perfil } = await admin.from("profiles").select("credits").eq("user_id", user.id).single();
  if (perfil.credits < 1) {
    return new Response(JSON.stringify({ error: "sem créditos" }), { status: 402, headers: corsHeaders });
  }

  const { titulo } = await req.json();
  const consulta = `select id, title, content from notes where user_id = '${user.id}' and title ilike '%${titulo}%'`;
  const { data: notas } = await admin.rpc("run_export", { query: consulta });

  await admin.from("profiles").update({ credits: perfil.credits - 1 }).eq("user_id", user.id);

  return new Response(JSON.stringify({ notas }), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
});
