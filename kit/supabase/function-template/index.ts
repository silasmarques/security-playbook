// Template de Edge Function segura — copiar a pasta e trocar o passo 7.
// Norma: stack/edge-functions-deno.md R1/P1, core/api-security.md P1.
// Rota Bearer-only: autentica só por `Authorization: Bearer`, sem cookie de
// sessão — imune a CSRF por desenho (api-security R9).
// #region template
import { createClient } from "@supabase/supabase-js";
import { corsFromEnv } from "../../web/cors.ts";
import { withErrorBoundary } from "../../web/error-boundary.ts";
import { mustGetEnv } from "../../web/env.ts";
import { checkRateLimit, requireAccess } from "../guards.ts";
import { json, jsonError, readJsonCapped } from "../../web/http.ts";
import { logEvent } from "../../web/log.ts";
import { parseCreateNote } from "./schema.ts";

// Config lida no boot: env ausente derruba a função no deploy, não no 1º request.
const SUPABASE_URL = mustGetEnv("SUPABASE_URL");
const SUPABASE_ANON_KEY = mustGetEnv("SUPABASE_ANON_KEY");
const corsHeadersFor = corsFromEnv();

Deno.serve(withErrorBoundary(async (req, { requestId }) => {
  const cors = corsHeadersFor(req);

  // 1. Preflight
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors });
  // 2. Método
  if (req.method !== "POST") return jsonError(405, "Método não permitido", cors, requestId);

  // 3. Autenticação — client com o token DO CHAMADOR; getUser valida no servidor de auth
  const authorization = req.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ")) return jsonError(401, "Autenticação necessária", cors, requestId);
  const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    global: { headers: { Authorization: authorization } },
    auth: { persistSession: false, autoRefreshToken: false },
  });
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) return jsonError(401, "Autenticação necessária", cors, requestId);

  // 4. Autorização centralizada (fail closed)
  if (!(await requireAccess(supabase))) {
    logEvent({ level: "warn", event: "access.denied", requestId, userId: user.id, meta: { fn: "create-note" } });
    return jsonError(403, "Sem acesso", cors, requestId);
  }

  // 5. Rate limit ANTES de ler e processar o payload
  if (!(await checkRateLimit(supabase, "create-note"))) {
    logEvent({ level: "warn", event: "ratelimit.hit", requestId, userId: user.id, meta: { action: "create-note" } });
    return jsonError(429, "Limite de uso atingido. Tente mais tarde.", cors, requestId);
  }

  // 6. Validação — body com teto de bytes, depois schema
  const input = parseCreateNote(await readJsonCapped(req, 100_000));
  if (!input) return jsonError(400, "Dados inválidos", cors, requestId);

  // 7. Lógica de negócio — identidade vem de user.id (token), NUNCA do body.
  //    Client do usuário: a RLS é a rede de segurança por baixo do filtro.
  const { data, error } = await supabase.from("qa_notes")
    .insert({ user_id: user.id, title: input.title, content: input.content })
    .select("id").single();
  if (error) throw new Error(`insert qa_notes: ${error.message}`); // o boundary loga e responde 500 genérico

  // 8. Resposta — json() já inclui os security headers
  return json(201, { id: data.id }, cors);
}, { headersFor: corsHeadersFor }));
// #endregion template
