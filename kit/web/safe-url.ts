// URLs dinâmicas no frontend: href seguro e redirect pós-login.
// Norma: core/frontend-security.md R2/P2, stack/react-typescript.md R7/P4.
// Testes: kit/tests/frontend.test.ts.

// #region safeHref
/** Só http(s) vira href. `javascript:`, `data:`, `vbscript:` executam código no
 *  clique. `base` é a origem da página (`window.location.origin`). */
export function safeHref(raw: string | null | undefined, base: string): string {
  if (!raw) return "#";
  try {
    const url = new URL(raw.trim(), base);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : "#";
  } catch {
    return "#";
  }
}
// <a href={safeHref(item.link, window.location.origin)} target="_blank" rel="noopener noreferrer">
// #endregion safeHref

// #region safeNext
/** Destino pós-login: só caminho INTERNO. Resolve contra a própria origem e
 *  confere que continuou nela — `//evil.com`, `/\evil.com` e `/%09/evil.com`
 *  parecem caminhos e o navegador os trata como outro site. */
export function safeNext(next: unknown, origin: string): string {
  if (typeof next !== "string" || !next.startsWith("/")) return "/";
  try {
    const url = new URL(next, origin);
    if (url.origin !== new URL(origin).origin) return "/";
    return url.pathname + url.search + url.hash;
  } catch {
    return "/";
  }
}
// #endregion safeNext
