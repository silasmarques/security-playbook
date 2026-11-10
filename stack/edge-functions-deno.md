---
owasp: [A01, A02, A05, A10]
last-review: 2026-11-10
sources:
  - https://supabase.com/docs/guides/functions
  - https://supabase.com/docs/guides/functions/secrets
  - https://supabase.com/docs/reference/javascript/auth-getclaims
  - https://docs.deno.com/runtime/fundamentals/security/
---

# Supabase Edge Functions (Deno)

> Cada Edge Function é um endpoint público na internet. A segurança vem de um prólogo padronizado e de helpers compartilhados em `_shared/` — função que reimplementa auth/CORS/validação à mão é função com bug de segurança esperando deploy.

## Regras

- **R1 — MUST** toda função executa o mesmo prólogo, na mesma ordem: preflight CORS → método → autenticação → acesso → rate limit → validação de input (`../core/api-security.md` R1). Partir do template P1 é o caminho feliz.
- **R2 — MUST** secrets só via env, definidos com `supabase secrets set`, lidos por `mustGetEnv`. **NEVER** hardcoded, **NEVER** com fallback (`?? "dev-key"` roda silenciosamente inseguro em prod). Config obrigatória é lida no boot do módulo: faltou, a função não sobe.
- **R3 — MUST** fetch para URL dinâmica passa por `safeFetch` (`../core/authorization.md` P2): redirect manual revalidado por hop, teto de resposta e allowlist de host quando o destino é conhecido.
- **R4 — MUST** helpers de segurança vivem em `_shared/` e são a ÚNICA implementação. Função nova importa; não copia nem reimplementa. Os arquivos vêm do kit (`deno run --allow-read --allow-write kit/install.ts <projeto>`).
- **R5 — MUST** manter `verify_jwt = true` (default) e AINDA assim validar o usuário no código — defesa em profundidade. Desabilitar `verify_jwt` (webhooks externos) exige verificação própria (assinatura HMAC + janela de tempo, P3) e o porquê registrado no código.
- **R6 — MUST** toda função embrulhada no boundary de erro (P2) — erro interno nunca vaza, sempre tem requestId, e a resposta de erro carrega CORS e security headers.
- **R7 — MUST** funções que chamam IA aplicam rate limit + cap de custo ANTES da chamada ao modelo (`../core/api-security.md` P2). Em auditoria real de produção, esta é a lacuna nº 1.
- **R8 — MUST** validar a identidade no servidor de auth: `getUser()` (consulta o Auth a cada request) ou `getClaims()` (verifica a assinatura localmente — a doc oficial o recomenda quando o projeto usa chave de assinatura **assimétrica**; com chave simétrica ele também consulta o servidor). **NEVER** `getSession()` em código de servidor.

## Padrões prontos

### P1 — Template de Edge Function segura

<!-- kit: kit/supabase/function-template/index.ts#template -->
```typescript
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
```

O schema do exemplo, sem dependência (com zod no projeto, ver `../core/input-validation.md` P1):

<!-- kit: kit/supabase/function-template/schema.ts#schema -->
```typescript
export interface CreateNote { title: string; content: string }

const LIMITS = { TITLE: 500, CONTENT: 50_000 } as const;
const ALLOWED_KEYS = new Set(["title", "content"]);

/** Devolve o input validado ou `null`. Rejeita campo a mais: `{"role":"admin"}`
 *  junto do payload não "passa batido" para a camada de baixo. */
export function parseCreateNote(body: unknown): CreateNote | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const rec = body as Record<string, unknown>;
  if (Object.keys(rec).some((k) => !ALLOWED_KEYS.has(k))) return null;
  const { title, content } = rec;
  if (typeof title !== "string" || typeof content !== "string") return null;
  const t = title.trim();
  if (t.length < 1 || t.length > LIMITS.TITLE || content.length > LIMITS.CONTENT) return null;
  return { title: t, content };
}
```

> **Chaves novas:** além das env legadas (`SUPABASE_ANON_KEY`, `SUPABASE_SERVICE_ROLE_KEY`), a plataforma oferece `sb_publishable_...`/`sb_secret_...`. O template usa a legada por compatibilidade; ao migrar, trocar a origem da chave (`../core/secrets-config.md` P1) e reconferir no ambiente real (inegociável 16).

### P2 — CORS por allowlist e boundary de erro

<!-- kit: kit/web/cors.ts#cors -->
```typescript
/** Cria o resolvedor de headers CORS a partir de uma lista de origens exatas.
 *  Origem fora da lista NÃO recebe `Access-Control-Allow-Origin` — o header é
 *  omitido e o navegador bloqueia a leitura. Nunca responder "null": sandbox de
 *  iframe e `data:` enviam `Origin: null`, e ecoar "null" libera exatamente eles. */
export function createCors(allowedOrigins: readonly string[], opts: CorsOptions = {}) {
  const allowed = new Set(allowedOrigins.map((o) => o.trim()).filter(Boolean));
  if (allowed.has("*") || allowed.has("null")) {
    throw new Error("CORS: '*' e 'null' não são origens válidas para allowlist");
  }
  return function corsHeadersFor(req: Request): Record<string, string> {
    const origin = req.headers.get("Origin") ?? "";
    const headers: Record<string, string> = { "Vary": "Origin" }; // cache não mistura origens
    if (allowed.has(origin)) {
      headers["Access-Control-Allow-Origin"] = origin;
      headers["Access-Control-Allow-Methods"] = opts.methods ?? "POST, OPTIONS";
      headers["Access-Control-Allow-Headers"] = opts.headers ?? "authorization, content-type, apikey, x-client-info";
      headers["Access-Control-Max-Age"] = "600";
    }
    return headers;
  };
}

/** ALLOWED_ORIGINS="https://app.exemplo.com,https://staging.exemplo.com"
 *  Env ausente ou vazia FALHA o boot: função sem allowlist não sobe aberta
 *  nem "fechada em silêncio" (secrets-config R8). */
export function corsFromEnv(opts: CorsOptions = {}, source?: EnvSource) {
  const origins = mustGetEnv("ALLOWED_ORIGINS", source).split(",").map((o) => o.trim()).filter(Boolean);
  if (origins.length === 0) throw new Error("ALLOWED_ORIGINS sem nenhuma origem válida");
  return createCors(origins, opts);
}
```

<!-- kit: kit/web/error-boundary.ts#withErrorBoundary -->
```typescript
export function withErrorBoundary(
  handler: (req: Request, ctx: { requestId: string }) => Promise<Response> | Response,
  opts: BoundaryOptions = {},
): (req: Request) => Promise<Response> {
  return async (req) => {
    const requestId = crypto.randomUUID();
    try {
      return await handler(req, { requestId });
    } catch (error) {
      // Detalhe COMPLETO só no log do servidor, correlacionado pelo requestId:
      const report = opts.onError ??
        ((id, e) => console.error(JSON.stringify({ level: "error", event: "server.error", requestId: id, stack: e instanceof Error ? e.stack : String(e) })));
      try { report(requestId, error); } catch { /* o log não pode derrubar a resposta */ }

      let extra: Record<string, string> = {};
      try { extra = opts.headersFor?.(req) ?? {}; } catch { /* sem CORS é melhor que sem resposta */ }
      // Genérico para o cliente — o mesmo texto para QUALQUER exceção:
      return jsonError(500, "Erro interno. Tente novamente.", extra, requestId);
    }
  };
}
```

### P3 — Webhook externo: HMAC + janela de tempo em vez de JWT

<!-- ilustrativo -->
```typescript
// verify_jwt = false na config EXIGE isto no código. O provedor assina
// `${timestamp}.${body}`; conferimos a assinatura e a idade da mensagem.
const signature = req.headers.get("x-webhook-signature") ?? "";
const timestamp = req.headers.get("x-webhook-timestamp") ?? "";
const body = await req.text(); // o texto CRU: a assinatura cobre os bytes, não o JSON reserializado

const fresh = Math.abs(Date.now() - Number(timestamp) * 1000) < 5 * 60_000; // anti-replay
if (!fresh || !(await hmacVerify(`${timestamp}.${body}`, signature, mustGetEnv("WEBHOOK_SECRET")))) {
  return jsonError(401, "Assinatura inválida", {}, requestId);
}
// Só agora o conteúdo é confiável. E o evento é processado UMA vez: guardar o
// id do evento e ignorar repetição (o provedor reenvia).
```

O formato exato (nome dos headers, o que entra na assinatura) é do provedor — seguir a documentação dele. `hmacVerify` está em [kit/web/crypto.ts](../kit/web/crypto.ts).

## Anti-padrões

```typescript
// ❌ NUNCA: pular a checagem de acesso "porque é só leitura" [viola R1]
// Caso real de auditoria: usuário bloqueado seguia usando as funções de IA
// que não chamavam a checagem — bloqueio que não bloqueia.

// ❌ NUNCA: CORS copiado de exemplo [viola R1/P2]
const corsHeaders = { "Access-Control-Allow-Origin": "*" };

// ❌ NUNCA: fallback de secret [viola R2]
const key = Deno.env.get("ENCRYPTION_KEY") ?? "default-key";

// ❌ NUNCA: identidade do body [viola R1]
const { userId } = await req.json(); // user.id JÁ existe, vindo do token verificado

// ❌ NUNCA: decidir com getSession() ou decodificando o JWT à mão [viola R8]
const { data: { session } } = await supabase.auth.getSession();
const claims = JSON.parse(atob(token.split(".")[1])); // payload sem assinatura conferida

// ❌ NUNCA: webhook com verify_jwt = false e sem assinatura [viola R5]
const evento = await req.json(); // qualquer pessoa na internet "aprova o pagamento"
```

## Checklist

- [ ] Função nova partiu do template P1 com o prólogo completo, na ordem?
- [ ] Helpers importados de `_shared/`, nada reimplementado?
- [ ] Nenhum secret hardcoded nem fallback de env; config obrigatória lida no boot?
- [ ] Fetch dinâmico passa por `safeFetch`?
- [ ] `verify_jwt` desabilitado só com HMAC + janela de tempo + justificativa no código?
- [ ] Função de IA tem rate limit + cap antes da chamada ao modelo?
- [ ] Identidade sempre de `user.id` (token validado no servidor), nunca do payload?
- [ ] Respostas de erro saem pelo boundary, com CORS e security headers?
