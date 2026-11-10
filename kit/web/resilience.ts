// Timeout em toda chamada externa + retry só de falha transitória.
// Norma: core/error-handling-resilience.md R4/R5/P2/P3. Testes: kit/tests/resilience.test.ts.

// #region fetchExternal
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
// #endregion fetchExternal

// #region withRetry
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
// #endregion withRetry
