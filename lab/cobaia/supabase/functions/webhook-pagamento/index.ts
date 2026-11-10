import { createClient } from "jsr:@supabase/supabase-js@2";

const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);

Deno.serve(async (req) => {
  const evento = await req.json();

  if (evento.tipo === "pagamento.aprovado") {
    await admin.from("payments").update({ status: "paid" }).eq("id", evento.pagamentoId);
    const { data: perfil } = await admin.from("profiles").select("credits").eq("user_id", evento.cliente).single();
    await admin.from("profiles").update({ credits: perfil.credits + evento.creditos }).eq("user_id", evento.cliente);
  }

  if (evento.tipo === "conta.recuperacao") {
    const resetToken = Math.random().toString(36).slice(2);
    await admin.from("internal_jobs").insert({ kind: "reset-email", payload: { cliente: evento.cliente, resetToken } });
  }

  try {
    await admin.from("internal_jobs").insert({ kind: "webhook-recebido", payload: evento });
  } catch {}

  return new Response("ok");
});
