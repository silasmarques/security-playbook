// Logger estruturado com redação automática e anti log-injection.
// Norma: core/logging-monitoring.md R2/R3/R4/P1. Testes: kit/tests/log.test.ts.

// #region logEvent
const SENSITIVE_KEY = /key|token|secret|password|senha|authorization|cookie|credential|session|jwt|bearer|otp/i;
const MAX_VALUE = 500;
const MAX_DEPTH = 4;

/** Redige por NOME da chave, em qualquer profundidade. Valores de texto são
 *  achatados em uma linha (sem \r\n — o atacante não forja linhas de log) e
 *  truncados. */
export function redact(value: unknown, depth = 0): unknown {
  if (typeof value === "string") {
    // deno-lint-ignore no-control-regex
    return value.replace(/[\u0000-\u001f\u007f\u2028\u2029]+/g, " ").slice(0, MAX_VALUE);
  }
  if (value === null || typeof value !== "object") return value;
  if (depth >= MAX_DEPTH) return "[TRUNCATED]";
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => redact(v, depth + 1));
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).slice(0, 50).map(([k, v]) => [
      redact(k), SENSITIVE_KEY.test(k) ? "[REDACTED]" : redact(v, depth + 1),
    ]),
  );
}

export interface LogInput {
  level: "info" | "warn" | "error";
  event: string;            // ex.: "auth.login_failed", "access.denied", "ratelimit.hit"
  requestId: string;
  userId?: string;
  meta?: Record<string, unknown>;
}

export function formatLogLine(input: LogInput, now = new Date()): string {
  return JSON.stringify({
    ts: now.toISOString(),
    level: input.level,
    event: redact(input.event),
    requestId: redact(input.requestId),
    userId: input.userId === undefined ? undefined : redact(input.userId),
    meta: redact(input.meta ?? {}),
  });
}

export function logEvent(input: LogInput): void {
  console[input.level](formatLogLine(input));
}
// #endregion logEvent
