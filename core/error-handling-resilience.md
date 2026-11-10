---
owasp: [A10]
last-review: 2026-11-10
sources:
  - https://owasp.org/Top10/2025/
  - https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html
---

# Tratamento de Erro e Resiliência

> Mishandling of Exceptional Conditions estreou como A10 na OWASP 2025: sistemas seguros no caminho feliz e escancarados quando algo falha. A pergunta deste módulo é sempre "e quando der errado?" — e a resposta nunca pode ser "deixa passar".

## Regras

- **R1 — MUST** fail closed: erro/exceção DENTRO de uma checagem de segurança (auth, acesso, validação) resulta em NEGAR. "Deu erro na checagem, então deixa passar" é a definição de bypass.
- **R2 — NEVER** expor ao cliente stack trace, mensagem interna de exceção, SQL, paths ou versões. Cliente recebe mensagem genérica + `requestId`; o detalhe completo vai para o log do servidor.
- **R3 — NEVER** catch vazio ou catch-and-continue silencioso em caminho de segurança ou escrita de dados. Capturou → logou → decidiu explicitamente (propagar, negar ou degradar).
- **R4 — MUST** timeout em TODA chamada externa (`AbortSignal.timeout` no fetch; `statement_timeout` em queries longas). Sem timeout, a lentidão do parceiro vira o SEU DoS.
- **R5 — MUST** retry apenas para falha transitória (408, 429, 5xx, rede), com backoff exponencial + jitter e máximo de tentativas. Exceção que não é de serviço externo (bug, negação de acesso) **não** se repete. **NEVER** retry de operação não-idempotente sem idempotency key — retry de pagamento sem proteção = cobrança dupla.
- **R6 — MUST** abortar em estado impossível (`throw`) em vez de seguir com dado inconsistente. Continuar "para não quebrar" corrompe dados e mascara ataque.
- **R7 — MUST** handlers globais (`unhandledrejection`/`error`) que logam com contexto e degradam graciosamente — nada de processo caindo sem registro.
- **R8 — MUST** limites de recursos derivados de input externo: tamanho de payload, número de itens processados, profundidade de recursão, tamanho de página (`api-security.md` R5).

## Padrões prontos

### P1 — Boundary de erro para handlers

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

### P2 — Chamada externa com timeout e falha tipada

<!-- kit: kit/web/resilience.ts#fetchExternal -->
```typescript
export class ExternalServiceError extends Error {
  constructor(message: string, readonly status: number) {
    super(message);
    this.name = "ExternalServiceError";
  }
}

/** fetch para destino FIXO e confiável (API de parceiro). Para URL que vem de
 *  fora, usar `safeFetch` de ./ssrf.ts — este aqui não valida destino. */
export async function fetchExternal(
  url: string,
  init: RequestInit = {},
  opts: { timeoutMs?: number; fetchImpl?: typeof fetch } = {},
): Promise<Response> {
  const timeoutMs = opts.timeoutMs ?? 10_000;
  let res: Response;
  try {
    res = await (opts.fetchImpl ?? fetch)(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
  } catch (e) {
    if (e instanceof DOMException && (e.name === "TimeoutError" || e.name === "AbortError")) {
      throw new ExternalServiceError(`timeout após ${timeoutMs}ms`, 504);
    }
    throw new ExternalServiceError("falha de rede", 0); // DNS, conexão recusada, TLS
  }
  if (!res.ok) {
    await res.body?.cancel();
    throw new ExternalServiceError(`status ${res.status}`, res.status);
  }
  return res;
}
```

### P3 — Retry com backoff exponencial + jitter (só transitório)

<!-- kit: kit/web/resilience.ts#withRetry -->
```typescript
const RETRYABLE = new Set([0, 408, 429, 500, 502, 503, 504]); // 0 = rede

/** Pré-condição: `fn` é IDEMPOTENTE (leitura, upsert com chave, escrita com
 *  idempotency key). Retry de operação não-idempotente duplica efeito. */
export async function withRetry<T>(
  fn: (attempt: number) => Promise<T>,
  opts: { maxAttempts?: number; baseMs?: number; maxMs?: number; sleep?: (ms: number) => Promise<void> } = {},
): Promise<T> {
  const maxAttempts = opts.maxAttempts ?? 3;
  const sleep = opts.sleep ?? ((ms) => new Promise<void>((r) => setTimeout(r, ms)));
  for (let attempt = 1; ; attempt++) {
    try {
      return await fn(attempt);
    } catch (e) {
      // Só ExternalServiceError transitório repete. Qualquer outra exceção é
      // bug ou negação — propaga na hora (repetir mascararia o problema).
      const transient = e instanceof ExternalServiceError && RETRYABLE.has(e.status);
      if (!transient || attempt >= maxAttempts) throw e;
      const backoff = Math.min((opts.baseMs ?? 500) * 2 ** (attempt - 1), opts.maxMs ?? 8000);
      await sleep(backoff + Math.random() * backoff * 0.25); // jitter: evita rajada sincronizada
    }
  }
}
```

## Anti-padrões

```typescript
// ❌ NUNCA: fail open em checagem de segurança [viola R1]
async function canAccess(userId: string): Promise<boolean> {
  try {
    return await checkAccess(userId);
  } catch {
    return true; // banco fora do ar = todo mundo é admin
  }
}

// ❌ NUNCA: catch vazio [viola R3]
try { await audit.log(event); } catch {}  // trilha de auditoria que falha em silêncio

// ❌ NUNCA: erro real para o cliente [viola R2]
catch (e) { return res.status(500).send(e.message); }
// "duplicate key value violates unique constraint users_email_key" → enumeração + schema

// ❌ NUNCA: loop dirigido por input externo sem teto [viola R8]
while (cursor) { cursor = await fetchPage(cursor); } // resposta maliciosa = loop infinito
```

## Checklist

- [ ] Falha em checagem de segurança resulta em negar (fail closed)?
- [ ] Respostas de erro genéricas + requestId; detalhe só no log?
- [ ] Nenhum catch vazio/silencioso no diff?
- [ ] Toda chamada externa com timeout explícito?
- [ ] Retry só em falha transitória, com backoff+jitter e teto, sobre operação idempotente?
- [ ] Estados impossíveis abortam em vez de continuar?
- [ ] Loops/recursões dirigidos por dado externo têm teto?
