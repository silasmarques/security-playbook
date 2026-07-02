---
owasp: [A10]
last-review: 2026-06-11
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
- **R5 — MUST** retry apenas para falha transitória (429, 5xx, rede), com backoff exponencial + jitter e máximo de tentativas. **NEVER** retry de operação não-idempotente sem idempotency key — retry de pagamento sem proteção = cobrança dupla.
- **R6 — MUST** abortar em estado impossível (`throw`) em vez de seguir com dado inconsistente. Continuar "para não quebrar" corrompe dados e mascara ataque.
- **R7 — MUST** handlers globais (`unhandledrejection`/`error`) que logam com contexto e degradam graciosamente — nada de processo caindo sem registro.
- **R8 — MUST** limites de recursos derivados de input externo: tamanho de payload, número de itens processados, profundidade de recursão, tamanho de página (`api-security.md` R5).

## Padrões prontos

### P1 — Boundary de erro para handlers (Edge Function)

```typescript
export function withErrorBoundary(
  handler: (req: Request) => Promise<Response>,
): (req: Request) => Promise<Response> {
  return async (req) => {
    const requestId = crypto.randomUUID();
    try {
      return await handler(req);
    } catch (error) {
      // Detalhe COMPLETO no log do servidor, correlacionado:
      console.error(`[${requestId}]`, error instanceof Error ? error.stack : error);
      // Genérico para o cliente:
      return new Response(
        JSON.stringify({ error: { code: 500, message: "Erro interno. Tente novamente.", requestId } }),
        { status: 500, headers: { "Content-Type": "application/json" } },
      );
    }
  };
}

Deno.serve(withErrorBoundary(async (req) => {
  /* handler normal — todo caminho retorna Response */
  return new Response("ok");
}));
```

### P2 — Fetch com timeout e distinção de falhas

```typescript
async function fetchExternal(url: string, init: RequestInit = {}, timeoutMs = 10_000) {
  try {
    const res = await fetch(url, { ...init, signal: AbortSignal.timeout(timeoutMs) });
    if (!res.ok) throw new ExternalServiceError(`status ${res.status}`, res.status);
    return res;
  } catch (e) {
    if (e instanceof DOMException && e.name === "TimeoutError") {
      throw new ExternalServiceError(`timeout após ${timeoutMs}ms`, 504);
    }
    throw e; // rede/DNS — deixa o boundary logar e responder genérico
  }
}
```

### P3 — Retry com backoff exponencial + jitter (só transitório)

```typescript
const RETRYABLE = new Set([429, 500, 502, 503, 504]);

async function withRetry<T>(fn: () => Promise<T>, maxAttempts = 3): Promise<T> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      return await fn();
    } catch (e) {
      lastError = e;
      const status = e instanceof ExternalServiceError ? e.status : 0;
      const transient = RETRYABLE.has(status) || status === 0; // 0 = rede
      if (!transient || attempt === maxAttempts) throw e;
      const backoff = Math.min(1000 * 2 ** (attempt - 1), 8000);
      await new Promise((r) => setTimeout(r, backoff + Math.random() * 500)); // jitter
    }
  }
  throw lastError;
}
// Pré-condição: fn é idempotente (leitura, upsert com chave) — senão, NÃO usar.
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
