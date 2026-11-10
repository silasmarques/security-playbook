import { createClient } from "jsr:@supabase/supabase-js@2";
import { jwtDecode } from "npm:jwt-decode@4";
import { corsHeaders } from "../_shared/cors.ts";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  const token = (req.headers.get("Authorization") ?? "").replace("Bearer ", "");
  if (!token) return new Response("Unauthorized", { status: 401, headers: corsHeaders });
  const claims = jwtDecode<{ sub: string }>(token);

  const url = new URL(req.url);
  const { data: notes } = await admin
    .from("notes")
    .select("id, title, created_at")
    .eq("user_id", claims.sub)
    .order("created_at", { ascending: false })
    .limit(Number(url.searchParams.get("limit") ?? 20));

  return new Response(JSON.stringify(notes), { headers: { ...corsHeaders, "Content-Type": "application/json" } });
});
