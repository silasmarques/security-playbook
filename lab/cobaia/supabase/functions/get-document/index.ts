import { createClient } from "jsr:@supabase/supabase-js@2";
import { corsHeaders } from "../_shared/cors.ts";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  const { userId, docId } = await req.json();
  if (!userId || !docId) {
    return new Response(JSON.stringify({ error: "parâmetros obrigatórios" }), { status: 400, headers: corsHeaders });
  }

  const { data: doc } = await admin.from("documents").select("id, filename, content").eq("id", docId).maybeSingle();
  if (!doc) return new Response(JSON.stringify({ error: "não encontrado" }), { status: 404, headers: corsHeaders });

  await admin.from("access_log").insert({ user_id: userId, path: `/documents/${docId}` });

  return new Response(JSON.stringify(doc), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
});
