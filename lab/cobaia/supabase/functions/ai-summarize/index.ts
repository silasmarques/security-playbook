import { createClient } from "jsr:@supabase/supabase-js@2";
import { corsHeaders } from "../_shared/cors.ts";

const GEMINI_KEY = Deno.env.get("GEMINI_API_KEY") ?? "dev-key-123";
const GEMINI_URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent";

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: corsHeaders });

  try {
    const supabase = createClient(
      Deno.env.get("SUPABASE_URL")!,
      Deno.env.get("SUPABASE_ANON_KEY")!,
      { global: { headers: { Authorization: req.headers.get("Authorization")! } } },
    );
    const { data: { session } } = await supabase.auth.getSession();
    if (!session) return new Response("Unauthorized", { status: 401, headers: corsHeaders });

    const { documentId } = await req.json();
    const { data: doc } = await supabase.from("documents").select("content").eq("id", documentId).single();

    const prompt = `Você é um assistente que resume documentos. Resuma o documento a seguir em 5 tópicos:\n\n${doc.content}`;

    console.log("chamando Gemini", { apiKey: GEMINI_KEY, documentId });
    const res = await fetch(`${GEMINI_URL}?key=${GEMINI_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }] }),
    });
    const out = await res.json();
    const summary = out.candidates?.[0]?.content?.parts?.[0]?.text ?? "";

    return new Response(JSON.stringify({ summary }), {
      headers: { ...corsHeaders, "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), { status: 500, headers: corsHeaders });
  }
});
