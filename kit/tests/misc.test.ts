import { assert, assertEquals, assertFalse, assertRejects, assertThrows } from "@std/assert";
import { formatLogLine, redact } from "../web/log.ts";
import { validateUpload } from "../web/upload.ts";
import { ExternalServiceError, fetchExternal, withRetry } from "../web/resilience.ts";
import { checkRateLimit, requireAccess, writeAudit } from "../supabase/guards.ts";
import { mustGetEnv } from "../web/env.ts";
import { corsFromEnv } from "../web/cors.ts";
import { safeHref, safeNext } from "../web/safe-url.ts";

// ---------- log ----------
Deno.test("log: chaves sensíveis são redigidas em qualquer profundidade", () => {
  const line = formatLogLine({
    level: "warn", event: "auth.login_failed", requestId: "r1", userId: "u1",
    meta: {
      apiKey: "sk-live-123", Authorization: "Bearer abc", nested: { password: "hunter2", ok: "visível" },
      lista: [{ refresh_token: "t0k3n" }], senha: "abc", cookie: "sid=1",
    },
  });
  for (const leak of ["sk-live-123", "Bearer abc", "hunter2", "t0k3n", "sid=1"]) assertFalse(line.includes(leak), leak);
  assert(line.includes("visível"));
  assertEquals(JSON.parse(line).meta.nested.password, "[REDACTED]");
});

Deno.test("log: quebra de linha no valor não forja uma segunda linha de log", () => {
  const line = formatLogLine({
    level: "info", event: "search", requestId: "r1",
    meta: { query: 'x\n{"level":"error","event":"auth.bypass"}\r\n\u2028fim' },
  });
  assertEquals(line.split(/[\r\n\u2028\u2029]/).length, 1);
  assertEquals(JSON.parse(line).event, "search");
});

Deno.test("log: valor gigante é truncado; estrutura profunda e circular não derrubam", () => {
  assertEquals((redact("a".repeat(10_000)) as string).length, 500);
  const circ: Record<string, unknown> = {};
  circ.self = circ;
  assert(JSON.stringify(redact(circ)).includes("[TRUNCATED]"));
});

// ---------- upload ----------
const PDF = new TextEncoder().encode("%PDF-1.7\n%âãÏÓ\n1 0 obj");
const TXT = new TextEncoder().encode("texto simples com acentuação\n");
const EXE = new Uint8Array([0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00]);
const opts = { allowed: ["pdf", "txt"] as const, maxBytes: 10 * 1024 * 1024 };

Deno.test("upload: PDF e TXT legítimos passam e ganham nome gerado pelo servidor", () => {
  const a = validateUpload({ name: "Relatório Final.PDF", type: "application/pdf", size: 1234 }, PDF, opts);
  assert(a.ok && a.kind === "pdf" && /^[0-9a-f-]{36}\.pdf$/.test(a.storageName));
  const b = validateUpload({ name: "notas.txt", type: "text/plain; charset=utf-8", size: 20 }, TXT, opts);
  assert(b.ok && b.kind === "txt");
});

Deno.test("upload: nome do cliente nunca aparece no nome de storage (path traversal)", () => {
  const r = validateUpload({ name: "../../etc/passwd.pdf", type: "application/pdf", size: 10 }, PDF, opts);
  assert(r.ok);
  assertFalse(r.storageName.includes("..") || r.storageName.includes("/") || r.storageName.includes("passwd"));
});

Deno.test("upload: rejeições — cada dimensão sozinha reprova", () => {
  const casos: Array<[string, Parameters<typeof validateUpload>[0], Uint8Array]> = [
    ["executável renomeado para .pdf", { name: "fatura.pdf", type: "application/pdf", size: 8 }, EXE],
    ["binário renomeado para .txt", { name: "a.txt", type: "text/plain", size: 8 }, EXE],
    ["extensão fora da allowlist", { name: "a.exe", type: "application/pdf", size: 8 }, PDF],
    ["dupla extensão terminando em proibida", { name: "a.pdf.html", type: "application/pdf", size: 8 }, PDF],
    ["content-type não bate com a extensão", { name: "a.pdf", type: "text/plain", size: 8 }, PDF],
    ["tipo permitido no kit mas não nesta rota (png)", { name: "a.png", type: "image/png", size: 8 }, PDF],
    ["sem extensão", { name: "arquivo", type: "application/pdf", size: 8 }, PDF],
    ["vazio", { name: "a.pdf", type: "application/pdf", size: 0 }, PDF],
    ["acima do teto", { name: "a.pdf", type: "application/pdf", size: opts.maxBytes + 1 }, PDF],
    ["tamanho não inteiro", { name: "a.pdf", type: "application/pdf", size: NaN }, PDF],
    ["sem bytes para conferir", { name: "a.pdf", type: "application/pdf", size: 8 }, new Uint8Array()],
  ];
  for (const [nome, file, head] of casos) assertEquals(validateUpload(file, head, opts).ok, false, nome);
});

// ---------- resiliência ----------
const noSleep = () => Promise.resolve();

Deno.test("retry: repete só falha transitória e para no teto", async () => {
  let n = 0;
  const r = await withRetry(() => { n++; if (n < 3) throw new ExternalServiceError("503", 503); return Promise.resolve("ok"); }, { sleep: noSleep });
  assertEquals([r, n], ["ok", 3]);

  n = 0;
  await assertRejects(() => withRetry(() => { n++; throw new ExternalServiceError("503", 503); }, { sleep: noSleep, maxAttempts: 4 }), ExternalServiceError);
  assertEquals(n, 4);
});

Deno.test("retry: 4xx e exceção comum NÃO repetem", async () => {
  for (const err of [new ExternalServiceError("400", 400), new ExternalServiceError("403", 403), new Error("bug"), new TypeError("x")]) {
    let n = 0;
    await assertRejects(() => withRetry(() => { n++; throw err; }, { sleep: noSleep }));
    assertEquals(n, 1, String(err));
  }
});

Deno.test("retry: backoff cresce e respeita o teto", async () => {
  const waits: number[] = [];
  await assertRejects(() => withRetry(() => { throw new ExternalServiceError("x", 0); }, {
    maxAttempts: 6, baseMs: 100, maxMs: 400, sleep: (ms) => { waits.push(ms); return Promise.resolve(); },
  }));
  assertEquals(waits.length, 5);
  assert(waits[0]! >= 100 && waits[0]! <= 125);
  assert(waits[1]! >= 200 && waits[1]! <= 250);
  for (const w of waits.slice(2)) assert(w >= 400 && w <= 500);
});

Deno.test("fetchExternal: status de erro, rede e timeout viram ExternalServiceError tipado", async () => {
  const impl = (r: () => Promise<Response>) => (() => r()) as unknown as typeof fetch;
  const e1 = await assertRejects(() => fetchExternal("https://api/x", {}, { fetchImpl: impl(() => Promise.resolve(new Response("x", { status: 503 }))) }), ExternalServiceError);
  assertEquals(e1.status, 503);
  const e2 = await assertRejects(() => fetchExternal("https://api/x", {}, { fetchImpl: impl(() => Promise.reject(new TypeError("dns"))) }), ExternalServiceError);
  assertEquals(e2.status, 0);
  const lento = ((_u: unknown, init?: RequestInit) =>
    new Promise<Response>((_res, rej) => init!.signal!.addEventListener("abort", () => rej(init!.signal!.reason)))) as unknown as typeof fetch;
  const e3 = await assertRejects(() => fetchExternal("https://api/x", {}, { fetchImpl: lento, timeoutMs: 20 }), ExternalServiceError);
  assertEquals(e3.status, 504);
  const ok = await fetchExternal("https://api/x", {}, { fetchImpl: impl(() => Promise.resolve(new Response("ok"))) });
  assertEquals(await ok.text(), "ok");
});

// ---------- guardas ----------
const rpc = (result: { data: unknown; error: unknown } | Error) => ({
  rpc: () => result instanceof Error ? Promise.reject(result) : Promise.resolve(result),
});

Deno.test("guardas: só `true` estrito libera; todo o resto nega (fail closed)", async () => {
  assert(await requireAccess(rpc({ data: true, error: null })));
  assert(await checkRateLimit(rpc({ data: true, error: null }), "ai-chat"));
  for (const r of [
    { data: false, error: null }, { data: null, error: null }, { data: "true", error: null }, { data: 1, error: null },
    { data: [{ can_access: true }], error: null }, { data: true, error: { message: "boom" } }, new Error("rede"),
  ]) {
    assertFalse(await requireAccess(rpc(r)), JSON.stringify(r));
    assertFalse(await checkRateLimit(rpc(r), "ai-chat"), JSON.stringify(r));
  }
});

Deno.test("writeAudit: falha no insert LANÇA (trilha não falha em silêncio)", async () => {
  const mk = (error: unknown) => ({ from: () => ({ insert: () => Promise.resolve({ error }) }) });
  const entry = { userId: "u1", action: "connection.create", resource: "c:1", requestId: "r1" };
  await writeAudit(mk(null), entry);
  await assertRejects(() => writeAudit(mk({ message: "permission denied" }), entry));
});

Deno.test("mustGetEnv: ausente ou em branco lança; presente devolve", () => {
  const env = (vars: Record<string, string>) => (name: string) => vars[name];
  assertEquals(mustGetEnv("A", env({ A: "valor" })), "valor");
  assertThrows(() => mustGetEnv("A", env({ A: "   " })));
  assertThrows(() => mustGetEnv("A", env({})));
  Deno.env.set("KIT_TEST_RUNTIME", "do-runtime");
  assertEquals(mustGetEnv("KIT_TEST_RUNTIME"), "do-runtime"); // fonte padrão: o runtime
});

Deno.test("corsFromEnv: sem ALLOWED_ORIGINS a função NÃO sobe", () => {
  const env = (vars: Record<string, string>) => (name: string) => vars[name];
  assertThrows(() => corsFromEnv({}, env({})));
  assertThrows(() => corsFromEnv({}, env({ ALLOWED_ORIGINS: " , " })));
  assertThrows(() => corsFromEnv({}, env({ ALLOWED_ORIGINS: "*" })));
  const cors = corsFromEnv({}, env({ ALLOWED_ORIGINS: "https://a.com, https://b.com" }));
  assertEquals(cors(new Request("https://f/x", { headers: { Origin: "https://b.com" } }))["Access-Control-Allow-Origin"], "https://b.com");
});

// ---------- frontend ----------
const ORIGIN = "https://app.exemplo.com";

Deno.test("safeHref: só http(s) passa", () => {
  assertEquals(safeHref("https://exemplo.com/a", ORIGIN), "https://exemplo.com/a");
  assertEquals(safeHref("/interno", ORIGIN), "https://app.exemplo.com/interno");
  for (const bad of ["javascript:alert(1)", " JaVaScRiPt:alert(1)", "java\tscript:alert(1)", "data:text/html,<script>1</script>", "vbscript:x", "file:///etc/passwd", null, undefined, ""]) {
    assertEquals(safeHref(bad, ORIGIN), "#", String(bad));
  }
});

Deno.test("safeNext: só caminho da própria origem", () => {
  assertEquals(safeNext("/painel?aba=2#x", ORIGIN), "/painel?aba=2#x");
  for (const bad of ["//evil.com", "//evil.com/painel?x=1", "/\\evil.com/painel", "/\t/evil.com/painel", "https://evil.com", "javascript:alert(1)", "evil.com", "", null, 42, undefined]) {
    assertEquals(safeNext(bad, ORIGIN), "/", String(bad));
  }
});
