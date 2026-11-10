// Boundary de erro: nada interno vaza, toda falha tem requestId, e a resposta
// de erro carrega CORS + security headers (senão o navegador esconde o requestId).
// Norma: core/error-handling-resilience.md R2/P1. Testes: kit/tests/http.test.ts.

import { jsonError } from "./http.ts";

export interface BoundaryOptions {
  /** Headers por request (tipicamente o CORS). Se lançar, é ignorado. */
  headersFor?: (req: Request) => Record<string, string>;
  /** Destino do detalhe do erro. Default: console.error. */
  onError?: (requestId: string, error: unknown) => void;
}

// #region withErrorBoundary
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
// #endregion withErrorBoundary
