---
owasp: [A01, A02, A05, A10]
last-review: 2026-06-11
sources:
  - https://supabase.com/docs/guides/functions
  - https://supabase.com/docs/guides/functions/secrets
  - https://docs.deno.com/runtime/fundamentals/security/
---

# Supabase Edge Functions (Deno)

> Cada Edge Function é um endpoint público na internet. A segurança vem de um prólogo padronizado e de helpers compartilhados em `_shared/` — função que reimplementa auth/CORS/validação à mão é função com bug de segurança esperando deploy.

## Regras

- **R1 — MUST** toda função executa o mesmo prólogo, na mesma ordem: CORS preflight → método → autenticação (`getUser`) → `requireAccess` → rate limit → validação de input. Ver o template P1 — copiá-lo é o caminho feliz.
- **R2 — MUST** secrets só via `Deno.env.get()`, definidos com `supabase secrets set`. **NEVER** hardcoded, **NEVER** com fallback (`?? "dev-key"` roda silenciosamente inseguro em prod).
- **R3 — MUST** fetch para URL dinâmica passa pelo validador SSRF compartilhado (`../core/authorization.md` P2) — em Edge Functions não há resolução de DNS disponível, então a mitigação de rebinding é redirect manual revalidado por hop + allowlist de domínio quando o destino é conhecido.
- **R4 — MUST** helpers de segurança vivem em `_shared/` e são a ÚNICA implementação: `cors.ts`, `access-control.ts`, `validation.ts`, `ssrf-validator.ts`, `crypto.ts`. Função nova importa; não copia nem reimplementa.
- **R5 — MUST** manter `verify_jwt = true` (default) e AINDA assim chamar `getUser()` no código — defesa em profundidade. Desabilitar `verify_jwt` (webhooks externos) exige verificação própria (assinatura HMAC do webhook) e registro do porquê no código.
- **R6 — MUST** toda função embrulhada no boundary de erro padrão (`../core/error-handling-resilience.md` P1) — erro interno nunca vaza, sempre tem requestId.
- **R7 — MUST** funções que chamam IA aplicam rate limit + cap de custo ANTES da chamada ao modelo (`../core/api-security.md` P2). Em auditoria real de produção, esta é a lacuna nº 1.

## Padrões prontos

### P1 — Template de Edge Function segura

```typescript
// supabase/functions/create-artifact/index.ts
import { createClient } from "jsr:@supabase/supabase-js@2";
import { corsHeadersFor } from "../_shared/cors.ts";
import { requireAccess } from "../_shared/access-control.ts";
import { withErrorBoundary } from "../_shared/error-boundary.ts";
import { createArtifactSchema } from "../_shared/schemas.ts";

Deno.serve(withErrorBoundary(async (req) => {
  const corsHeaders = corsHeadersFor(req);

  // 1. Preflight
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });
  // 2. Método
  if (req.method !== "POST") return jsonError(405, "Método não permitido", corsHeaders);

  // 3. Autenticação — token do chamador, validado no servidor
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: req.headers.get("Authorization")! } } },
  );
  const { data: { user }, error: authError } = await supabase.auth.getUser();
  if (authError || !user) return jsonError(401, "Autenticação necessária", corsHeaders);

  // 4. Autorização centralizada
  const denied = await requireAccess(supabase, user.id, { corsHeaders });
  if (denied) return denied;

  // 5. Rate limit (obrigatório se a função for cara — IA, e-mail, export)
  const { data: allowed } = await supabase.rpc("check_and_increment", {
    _user_id: user.id, _action: "create-artifact", _limit: 60, _window: "1 hour",
  });
  if (!allowed) return jsonError(429, "Limite de uso atingido", corsHeaders);

  // 6. Validação
  const parsed = createArtifactSchema.safeParse(await req.json().catch(() => null));
  if (!parsed.success) return jsonError(400, "Dados inválidos", corsHeaders);

  // 7. Lógica de negócio — user.id vem do token, NUNCA do body
  // ...

  return new Response(JSON.stringify({ ok: true }), {
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}));
```

### P2 — `_shared/cors.ts` com allowlist por env

```typescript
// ALLOWED_ORIGINS="https://app.exemplo.com,https://staging.exemplo.com"
const allowed = new Set(
  (Deno.env.get("ALLOWED_ORIGINS") ?? "").split(",").map((o) => o.trim()).filter(Boolean),
);

export function corsHeadersFor(req: Request): Record<string, string> {
  const origin = req.headers.get("Origin") ?? "";
  return {
    // Origem fora da allowlist NÃO é ecoada — browser bloqueia a resposta.
    "Access-Control-Allow-Origin": allowed.has(origin) ? origin : "null",
    "Access-Control-Allow-Headers": "authorization, content-type",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Vary": "Origin",
  };
}
```

### P3 — Webhook externo: HMAC em vez de JWT

```typescript
// verify_jwt = false NA CONFIG exige isto no código (e o porquê documentado):
// Provedor manda assinatura do body; verificamos com timing-safe compare.
const signature = req.headers.get("x-webhook-signature") ?? "";
const body = await req.text();
const expected = await hmacSign(body, Deno.env.get("WEBHOOK_SECRET")!);
if (!timingSafeEqual(signature, expected)) {
  return jsonError(401, "Assinatura inválida", corsHeaders);
}
// + janela de timestamp anti-replay (ver core/crypto-data-protection.md P2)
```

## Anti-padrões

```typescript
// ❌ NUNCA: pular requireAccess "porque é só leitura" [viola R1]
// Caso real de auditoria: usuário bloqueado seguia usando as funções de IA
// que não chamavam a checagem de acesso — bloqueio que não bloqueia.

// ❌ NUNCA: CORS copiado de exemplo [viola R1/P2]
const corsHeaders = { "Access-Control-Allow-Origin": "*" }; // todo site pode chamar logado

// ❌ NUNCA: fallback de secret [viola R2]
const key = Deno.env.get("ENCRYPTION_KEY") ?? "default-key";

// ❌ NUNCA: identidade do body [viola R1]
const { userId } = await req.json(); // user.id JÁ existe, vindo do token verificado
```

## Checklist

- [ ] Função nova partiu do template P1 com o prólogo completo, na ordem?
- [ ] Helpers importados de `_shared/`, nada reimplementado?
- [ ] Nenhum secret hardcoded nem fallback de env?
- [ ] Fetch dinâmico passa pelo validador SSRF com redirect manual?
- [ ] `verify_jwt` desabilitado só com HMAC próprio + justificativa no código?
- [ ] Função de IA tem rate limit + cap antes da chamada ao modelo?
- [ ] Identidade sempre de `user.id` (token), nunca do payload?
