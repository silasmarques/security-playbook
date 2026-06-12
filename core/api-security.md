---
owasp: [A01, A02, A10]
last-review: 2026-06-11
sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
  - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
---

# Segurança de APIs

> Todo endpoint é porta de entrada. A regra de ouro: não existe endpoint "interno", "temporário" ou "que só o frontend chama" — se responde HTTP, será descoberto e atacado.

## Regras

- **R1 — MUST** todo endpoint, sem exceção: autenticação → autorização → validação de input → rate limiting. A ordem importa: rejeitar barato antes de processar caro.
- **R2 — MUST** rate limiting **por usuário** + cap de custo em operações caras (IA, e-mail, export, geração de relatório). Operação cara sem cap = fatura aberta e DoS econômico — a lacuna nº 1 encontrada em auditoria real de produção, elevada aqui a norma para todo projeto.
- **R3 — MUST** allowlist de métodos HTTP por rota; tudo fora dela responde 405. `OPTIONS` tratado explicitamente (preflight CORS).
- **R4 — MUST** erros padronizados: status correto + mensagem genérica + `requestId` correlacionável; o detalhe real vai para o log do servidor (`error-handling-resilience.md` R2).
- **R5 — MUST** paginação com teto imposto no servidor (`LIMIT least(pedido, 100)`). **NEVER** deixar o cliente controlar volume sem limite.
- **R6 — MUST** timeout explícito em toda chamada externa feita pelo endpoint; o handler responde mesmo com dependência travada.
- **R7 — MUST** security headers em toda resposta (`secrets-config.md` P2) e CORS por allowlist de origens.
- **R8 — MUST** escritas críticas que o cliente pode reenviar (pagamento, criação por retry automático) protegidas por idempotency key ou desenho idempotente.

## Padrões prontos

### P1 — Esqueleto de handler seguro (ordem canônica)

```typescript
Deno.serve(async (req) => {
  // 1. CORS preflight
  if (req.method === "OPTIONS") return new Response(null, { headers: corsHeaders });

  // 2. Método
  if (req.method !== "POST") {
    return jsonError(405, "Método não permitido");
  }

  // 3. Autenticação (authentication.md P1)
  const user = await getVerifiedUser(req);
  if (!user) return jsonError(401, "Autenticação necessária");

  // 4. Autorização (authorization.md P1)
  const denied = await requireAccess(supabase, user.id, { corsHeaders });
  if (denied) return denied;

  // 5. Rate limit ANTES de validar/processar payload caro
  const limited = await checkRateLimit(supabase, user.id, "create-artifact");
  if (limited) return jsonError(429, "Limite de uso atingido. Tente mais tarde.");

  // 6. Validação (input-validation.md P1)
  const parsed = schema.safeParse(await req.json());
  if (!parsed.success) return jsonError(400, "Dados inválidos");

  // 7. Lógica de negócio
  // ...

  // 8. Resposta com security headers
  return json(200, result);
});
```

### P2 — Rate limiting por usuário em Postgres (janela fixa)

```sql
CREATE TABLE usage_counters (
  user_id    uuid NOT NULL,
  action     text NOT NULL,
  window_start timestamptz NOT NULL,
  count      int  NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, action, window_start)
);

-- Atômico: incrementa e responde se passou do limite, em um round-trip.
CREATE OR REPLACE FUNCTION check_and_increment(
  _user_id uuid, _action text, _limit int, _window interval
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
DECLARE _window_start timestamptz := date_trunc('hour', now()); _count int;
BEGIN
  INSERT INTO usage_counters (user_id, action, window_start, count)
  VALUES (_user_id, _action, _window_start, 1)
  ON CONFLICT (user_id, action, window_start)
  DO UPDATE SET count = usage_counters.count + 1
  RETURNING count INTO _count;
  RETURN _count <= _limit;   -- true = pode seguir
END $$;
```

```typescript
const { data: allowed } = await supabase.rpc("check_and_increment", {
  _user_id: user.id, _action: "ai-chat", _limit: 30, _window: "1 hour",
});
if (!allowed) return jsonError(429, "Limite de uso atingido");
```

> Trade-off: janela fixa em Postgres é simples e suficiente para caps de custo
> (dezenas/min). Para rate limit de alta frequência (centenas/s), usar
> infraestrutura dedicada (Redis/upstash) — não reimplementar.

### P3 — Resposta de erro padrão

```typescript
function jsonError(status: number, message: string, requestId = crypto.randomUUID()) {
  // Detalhe NUNCA sai daqui — só status + mensagem genérica + correlação.
  return new Response(JSON.stringify({ error: { code: status, message, requestId } }), {
    status,
    headers: { ...corsHeaders, "Content-Type": "application/json" },
  });
}
// Mapa canônico: 400 dados inválidos · 401 não autenticado · 403 sem acesso ·
// 404 não encontrado (também para "existe mas não é seu") · 405 método ·
// 429 rate limit · 500 erro interno genérico.
```

## Anti-padrões

```typescript
// ❌ NUNCA: endpoint sem auth "porque só o frontend chama" [viola R1]
Deno.serve(async (req) => {
  const { userId } = await req.json();      // identidade do body = de quem atacar
  return json(200, await getDocuments(userId));
});

// ❌ NUNCA: volume controlado pelo cliente [viola R5]
const limit = Number(url.searchParams.get("limit")); // ?limit=10000000
const rows = await db.from("logs").select().limit(limit);

// ❌ NUNCA: vazar o erro real [viola R4]
catch (e) { return new Response(e.stack, { status: 500 }); }

// ❌ NUNCA: operação de IA sem cap "porque é beta" [viola R2]
const answer = await gemini.generate(prompt); // sem checkRateLimit antes
```

## Checklist

- [ ] Rota nova segue a ordem canônica do P1 (auth → acesso → rate limit → validação)?
- [ ] Operações caras têm rate limit por usuário e cap de custo?
- [ ] Métodos não permitidos respondem 405?
- [ ] Erros usam o formato padrão sem vazar internals?
- [ ] Paginação com teto do servidor?
- [ ] Chamadas externas com timeout?
- [ ] CORS allowlist + security headers na resposta?
