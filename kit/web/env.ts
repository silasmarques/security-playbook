// Configuração obrigatória: ausente = falhar o boot. Funciona em Deno, Node e Bun.
// Norma: core/secrets-config.md R8. Testes: kit/tests/misc.test.ts.

export type EnvSource = (name: string) => string | undefined;

const runtimeEnv: EnvSource = (name) => {
  const g = globalThis as {
    Deno?: { env: { get(n: string): string | undefined } };
    process?: { env: Record<string, string | undefined> };
  };
  return g.Deno ? g.Deno.env.get(name) : g.process?.env[name];
};

// #region mustGetEnv
/** Env obrigatória: ausente ou em branco LANÇA. Nunca `?? "valor-padrão"` —
 *  fallback de segredo roda em produção com chave conhecida, em silêncio. */
export function mustGetEnv(name: string, source: EnvSource = runtimeEnv): string {
  const value = source(name);
  if (value === undefined || value.trim() === "") {
    throw new Error(`variável de ambiente obrigatória ausente: ${name}`);
  }
  return value;
}
// #endregion mustGetEnv
