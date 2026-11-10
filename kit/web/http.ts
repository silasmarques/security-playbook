// Respostas HTTP padronizadas: security headers em TODA resposta (inegociável 14)
// e erro genérico + requestId (inegociável 7).
// Norma: core/api-security.md R4/P3, core/secrets-config.md P2. Testes: kit/tests/http.test.ts.

// #region securityHeaders
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
// #endregion securityHeaders

// #region json
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
// #endregion json

// #region readJsonCapped
/** Lê o body JSON com teto de bytes ANTES de fazer parse. Devolve `undefined`
 *  se exceder o teto ou não for JSON — o schema rejeita em seguida. */
export async function readJsonCapped(req: Request, maxBytes = 100_000): Promise<unknown> {
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (declared > maxBytes || !req.body) return undefined;
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) { await reader.cancel(); return undefined; }
    chunks.push(value);
  }
  const all = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { all.set(c, offset); offset += c.byteLength; }
  try { return JSON.parse(new TextDecoder().decode(all)); } catch { return undefined; }
}
// #endregion readJsonCapped
