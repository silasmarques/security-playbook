// Validação na fronteira sem dependência: `unknown` entra, tipo provado sai.
// Com zod no projeto, o equivalente está em core/input-validation.md P1.
// Testes: kit/tests/schema.test.ts.

// #region schema
export interface CreateNote { title: string; content: string }

const LIMITS = { TITLE: 500, CONTENT: 50_000 } as const;
const ALLOWED_KEYS = new Set(["title", "content"]);

/** Devolve o input validado ou `null`. Rejeita campo a mais: `{"role":"admin"}`
 *  junto do payload não "passa batido" para a camada de baixo. */
export function parseCreateNote(body: unknown): CreateNote | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const rec = body as Record<string, unknown>;
  if (Object.keys(rec).some((k) => !ALLOWED_KEYS.has(k))) return null;
  const { title, content } = rec;
  if (typeof title !== "string" || typeof content !== "string") return null;
  const t = title.trim();
  if (t.length < 1 || t.length > LIMITS.TITLE || content.length > LIMITS.CONTENT) return null;
  return { title: t, content };
}
// #endregion schema
