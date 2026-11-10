// CORS por allowlist. Norma: core/secrets-config.md R6, stack/edge-functions-deno.md P2.
// Testes: kit/tests/http.test.ts.
import { type EnvSource, mustGetEnv } from "./env.ts";

export interface CorsOptions {
  methods?: string;  // default "POST, OPTIONS"
  headers?: string;  // default "authorization, content-type, apikey, x-client-info"
}

// #region cors
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
// #endregion cors
