---
owasp: [A01, A02, A10]
last-review: 2026-11-10
sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/REST_Security_Cheat_Sheet.html
  - https://owasp.org/API-Security/editions/2023/en/0x11-t10/
  - https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin
---

# Segurança de APIs

> Todo endpoint é porta de entrada. A regra de ouro: não existe endpoint "interno", "temporário" ou "que só o frontend chama" — se responde HTTP, será descoberto e atacado.

## Regras

- **R1 — MUST** todo endpoint, sem exceção, executa o prólogo nesta ordem: **método → autenticação → autorização → rate limit → validação de input**. A ordem é do mais barato para o mais caro: negar antes de ler e processar payload. (Preflight CORS responde antes de tudo.)
- **R2 — MUST** rate limiting **por usuário** + cap de custo em operações caras (IA, e-mail, export, geração de relatório), aplicado ANTES do trabalho. O limite mora no servidor — nunca em argumento que o cliente consegue enviar. Operação cara sem cap = fatura aberta e DoS econômico — a lacuna nº 1 encontrada em auditoria real de produção.
- **R3 — MUST** allowlist de métodos HTTP por rota; tudo fora dela responde 405. `OPTIONS` tratado explicitamente (preflight CORS).
- **R4 — MUST** erros padronizados: status correto + mensagem genérica + `requestId` correlacionável; o detalhe real vai para o log do servidor (`error-handling-resilience.md` R2).
- **R5 — MUST** paginação com teto imposto no servidor (`Math.min(pedido, 100)`). **NEVER** deixar o cliente controlar volume sem limite.
- **R6 — MUST** timeout explícito em toda chamada externa feita pelo endpoint; o handler responde mesmo com dependência travada.
- **R7 — MUST** security headers em TODA resposta — inclusive as de erro — e CORS por allowlist de origens. Origem fora da lista não recebe `Access-Control-Allow-Origin`; **NEVER** responder `*` em rota autenticada nem o valor `null` (iframe em sandbox e `data:` enviam `Origin: null`).
- **R8 — MUST** escritas críticas que o cliente pode reenviar (pagamento, criação por retry automático) protegidas por idempotency key ou desenho idempotente.
- **R9 — MUST** endpoint que autentica via **cookie de sessão** (inclui apps SSR) tem defesa anti-CSRF: token sincronizado validado no servidor, **ou** `SameSite=Strict/Lax` como defesa primária apenas se o fluxo tolera. Endpoint que autentica **só via header `Authorization: Bearer`** é imune por desenho (o navegador não envia o header sozinho) — mas isso é decisão a declarar, não presumir: registrar em comentário que a rota é Bearer-only. Mutação sensível via `GET` é proibida.
- **R10 — MUST** operação de "checar e depois alterar" (saldo, cota, estoque, cupom de uso único) é **atômica**: um único comando no banco (`update … where saldo >= x returning`), ou transação com trava. Ler, decidir no código e gravar depois é corrida: duas requisições simultâneas passam pela mesma checagem.
- **R11 — MUST** body lido com teto de bytes ANTES do parse, e schema que rejeita campo desconhecido. Campo a mais aceito em silêncio é como `role: "admin"` chega à camada de baixo (mass assignment).

## Padrões prontos

### P1 — Handler seguro (ordem canônica)

Template completo e type-checado contra o SDK real. É o caminho feliz: copiar e trocar o passo 7.

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

### P2 — Rate limiting por usuário (janela fixa)

O limite fica numa tabela de regras; a função recebe só o nome da ação e conta para a identidade do token. Quem chamar a RPC direto só consegue gastar a **própria** cota de uma ação que existe.

<!-- kit: kit/supabase/sql/02_rate_limit.sql#rate_limit -->
```sql
create table public.rate_limits (
  action         text primary key check (char_length(action) between 1 and 64),
  max_calls      integer not null check (max_calls > 0),
  window_seconds integer not null check (window_seconds between 1 and 2678400)
);

create table public.usage_counters (
  user_id      uuid not null references auth.users (id) on delete cascade,
  action       text not null references public.rate_limits (action) on delete cascade,
  window_start timestamptz not null,
  count        integer not null default 0,
  primary key (user_id, action, window_start)
);

-- RLS ligada e NENHUMA policy: cliente não lê nem escreve. Os grants também
-- saem — duas travas independentes (inegociável 2 vale para tabela "interna").
alter table public.rate_limits enable row level security;
alter table public.usage_counters enable row level security;
revoke all on public.rate_limits, public.usage_counters from anon, authenticated;

-- Atômica: incrementa e responde em um round-trip. true = dentro do limite.
create function public.check_and_increment(_action text) returns boolean
language plpgsql security definer set search_path = '' as $$
declare
  _uid   uuid := auth.uid();
  _rule  public.rate_limits%rowtype;
  _start timestamptz;
  _count integer;
begin
  if _uid is null then
    raise exception 'not authenticated' using errcode = '28000';
  end if;
  select * into _rule from public.rate_limits r where r.action = _action;
  if not found then
    raise exception 'unknown rate limit action' using errcode = '22023'; -- ação sem regra = erro, não "liberado"
  end if;

  _start := to_timestamp(floor(extract(epoch from now()) / _rule.window_seconds) * _rule.window_seconds);

  insert into public.usage_counters as c (user_id, action, window_start, count)
  values (_uid, _action, _start, 1)
  on conflict (user_id, action, window_start) do update set count = c.count + 1
  returning c.count into _count;

  return _count <= _rule.max_calls;
end $$;

revoke execute on function public.check_and_increment(text) from public, anon;
grant execute on function public.check_and_increment(text) to authenticated;

-- Cada ação cara ganha uma linha (na migration da feature):
--   insert into public.rate_limits values ('ai-chat', 30, 3600);
-- Limpeza: apagar janelas antigas em job agendado
--   delete from public.usage_counters where window_start < now() - interval '35 days';
```

<!-- kit: kit/supabase/guards.ts#checkRateLimit -->
```typescript
/** `true` = dentro do limite. Chamar ANTES do trabalho caro. O limite e a
 *  janela moram no banco (tabela rate_limits) e o contador é do `auth.uid()`
 *  do token — ver kit/supabase/sql/02_rate_limit.sql. */
export async function checkRateLimit(client: RpcClient, action: string): Promise<boolean> {
  try {
    const { data, error } = await client.rpc("check_and_increment", { _action: action });
    return !error && data === true;
  } catch {
    return false;
  }
}
```

> Trade-off: janela fixa em Postgres é simples e suficiente para caps de custo (dezenas por minuto). Para rate limit de alta frequência (centenas por segundo) ou pré-autenticação por IP, usar a borda (WAF) ou infraestrutura dedicada — não reimplementar.

### P3 — Respostas padronizadas com security headers

<!-- kit: kit/web/http.ts#securityHeaders -->
```typescript
/** Headers de segurança para respostas de API (JSON). Para HTML, somar a CSP
 *  completa do host — ver core/frontend-security.md P3. */
export const API_SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  // API não renderiza nada: negar tudo e proibir enquadramento.
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Cache-Control": "no-store",
};
```

<!-- kit: kit/web/http.ts#json -->
```typescript
export function json(status: number, body: unknown, extraHeaders: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...extraHeaders, ...API_SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8" },
  });
}

/** Erro padronizado. `message` é texto FIXO escolhido pelo código — nunca
 *  `error.message` de uma exceção (isso vaza internals). */
export function jsonError(
  status: number,
  message: string,
  extraHeaders: Record<string, string> = {},
  requestId: string = crypto.randomUUID(),
): Response {
  return json(status, { error: { code: status, message, requestId } }, extraHeaders);
}
// Mapa canônico: 400 dados inválidos · 401 não autenticado · 403 sem acesso ·
// 404 não encontrado (também para "existe mas não é seu") · 405 método ·
// 413 payload grande demais · 429 rate limit · 500 erro interno genérico.
```

### P4 — Débito atômico (R10)

<!-- ilustrativo -->
```typescript
// Um comando só: a checagem e o débito acontecem juntos, dentro do banco.
// Duas requisições simultâneas → só uma encontra a linha com saldo suficiente.
const { data } = await supabase.rpc("debit_credit", { _amount: 1 });
if (data !== true) return jsonError(402, "Sem créditos");
// SQL da função: update public.wallets set credits = credits - _amount
//                where user_id = auth.uid() and credits >= _amount returning true;
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

// ❌ NUNCA: limite de uso vindo de quem chama [viola R2]
await supabase.rpc("check_and_increment", { _user_id: body.userId, _limit: body.limit });
// o cliente escolhe o próprio limite — e gasta a cota de outro usuário

// ❌ NUNCA: checar e depois debitar [viola R10]
if (perfil.credits < 1) return jsonError(402, "Sem créditos");
await gerarRelatorio();
await db.from("profiles").update({ credits: perfil.credits - 1 }); // 50 requisições em paralelo = 50 relatórios por 1 crédito

// ❌ NUNCA: "bloquear" origem respondendo null [viola R7]
"Access-Control-Allow-Origin": allowed.has(origin) ? origin : "null" // libera iframe sandbox e data:

// ❌ NUNCA: mutação de estado via GET em app com cookie de sessão [viola R9]
// GET /account/delete?confirm=1  → <img src="...account/delete?confirm=1"> dispara sozinho
```

## Checklist

- [ ] Rota nova segue a ordem canônica do P1 (método → auth → acesso → rate limit → validação)?
- [ ] Operações caras têm rate limit por usuário e cap de custo, com o limite definido no servidor?
- [ ] Métodos não permitidos respondem 405?
- [ ] Erros usam o formato padrão sem vazar internals?
- [ ] Paginação com teto do servidor?
- [ ] Chamadas externas com timeout?
- [ ] CORS por allowlist (sem `*`, sem `null`) e security headers em todas as respostas, inclusive erros?
- [ ] Rota com cookie de sessão tem token anti-CSRF? (Bearer-only → declarado em comentário)
- [ ] "Checar e alterar" é um comando atômico?
- [ ] Body com teto de bytes e schema que rejeita campo desconhecido?
