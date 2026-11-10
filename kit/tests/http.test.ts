import { assert, assertEquals, assertFalse, assertThrows } from "@std/assert";
import { createCors } from "../web/cors.ts";
import { API_SECURITY_HEADERS, json, jsonError, readJsonCapped } from "../web/http.ts";
import { withErrorBoundary } from "../web/error-boundary.ts";

const cors = createCors(["https://app.exemplo.com", "https://staging.exemplo.com"]);
const reqFrom = (origin?: string) =>
  new Request("https://fn.exemplo.com/x", { method: "POST", headers: origin ? { Origin: origin } : {} });

Deno.test("CORS: origem da allowlist é ecoada", () => {
  assertEquals(cors(reqFrom("https://app.exemplo.com"))["Access-Control-Allow-Origin"], "https://app.exemplo.com");
});

Deno.test("CORS: origem fora da allowlist NÃO recebe Allow-Origin (header omitido)", () => {
  for (const o of ["https://evil.com", "https://app.exemplo.com.evil.com", "http://app.exemplo.com", "https://APP.exemplo.com.", undefined]) {
    const h = cors(reqFrom(o));
    assertFalse("Access-Control-Allow-Origin" in h, `vazou para ${o}`);
    assertEquals(h["Vary"], "Origin");
  }
});

Deno.test("CORS: Origin 'null' (iframe sandbox, data:) nunca é liberada", () => {
  const h = cors(reqFrom("null"));
  assertFalse("Access-Control-Allow-Origin" in h);
  assertFalse(Object.values(h).includes("null"));
});

Deno.test("CORS: allowlist com '*' ou 'null' falha na criação", () => {
  assertThrows(() => createCors(["*"]));
  assertThrows(() => createCors(["https://ok.com", "null"]));
});

Deno.test("json/jsonError: toda resposta carrega os security headers", async () => {
  for (const res of [json(200, { ok: true }), jsonError(403, "Sem acesso")]) {
    for (const [k, v] of Object.entries(API_SECURITY_HEADERS)) assertEquals(res.headers.get(k), v);
    await res.body?.cancel();
  }
});

Deno.test("json: header extra não consegue sobrescrever um security header", () => {
  const res = json(200, {}, { "X-Content-Type-Options": "sniff-a-vontade", "Access-Control-Allow-Origin": "https://app.exemplo.com" });
  assertEquals(res.headers.get("X-Content-Type-Options"), "nosniff");
  assertEquals(res.headers.get("Access-Control-Allow-Origin"), "https://app.exemplo.com");
});

Deno.test("jsonError: formato padrão com requestId", async () => {
  const body = await jsonError(429, "Limite de uso atingido", {}, "req-1").json();
  assertEquals(body, { error: { code: 429, message: "Limite de uso atingido", requestId: "req-1" } });
});

Deno.test("error boundary: exceção vira 500 genérico — segredo da exceção não vaza", async () => {
  const logged: unknown[] = [];
  const handler = withErrorBoundary(
    () => { throw new Error('duplicate key value violates "users_email_key" senha=hunter2 at /srv/app/db.ts:42'); },
    { headersFor: cors, onError: (id, e) => logged.push([id, e]) },
  );
  const res = await handler(reqFrom("https://app.exemplo.com"));
  const text = await res.text();
  assertEquals(res.status, 500);
  for (const leak of ["duplicate", "users_email_key", "hunter2", "/srv/app", "db.ts"]) assertFalse(text.includes(leak));
  const body = JSON.parse(text);
  assertEquals(body.error.message, "Erro interno. Tente novamente.");
  // o mesmo requestId foi para o log, com o erro real
  assertEquals((logged[0] as [string, Error])[0], body.error.requestId);
  assert((logged[0] as [string, Error])[1].message.includes("hunter2"));
  // CORS + security headers presentes: o navegador consegue ler o requestId
  assertEquals(res.headers.get("Access-Control-Allow-Origin"), "https://app.exemplo.com");
  assertEquals(res.headers.get("X-Content-Type-Options"), "nosniff");
});

Deno.test("error boundary: rejeição assíncrona e falha do próprio logger também viram 500", async () => {
  const handler = withErrorBoundary(
    () => Promise.reject(new Error("x")),
    { onError: () => { throw new Error("logger quebrou"); }, headersFor: () => { throw new Error("cors quebrou"); } },
  );
  const res = await handler(reqFrom());
  assertEquals(res.status, 500);
  await res.body?.cancel();
});

Deno.test("error boundary: resposta normal passa intacta", async () => {
  const res = await withErrorBoundary(() => json(201, { id: 1 }))(reqFrom());
  assertEquals(res.status, 201);
  await res.body?.cancel();
});

Deno.test("readJsonCapped: body acima do teto ou inválido vira undefined", async () => {
  const mk = (body: string, headers: Record<string, string> = {}) =>
    new Request("https://fn/x", { method: "POST", body, headers });
  assertEquals(await readJsonCapped(mk('{"a":1}')), { a: 1 });
  assertEquals(await readJsonCapped(mk("{quebrado")), undefined);
  assertEquals(await readJsonCapped(mk(JSON.stringify({ a: "x".repeat(2000) })), 1000), undefined);
  assertEquals(await readJsonCapped(mk("{}", { "content-length": "999999" }), 1000), undefined);
  assertEquals(await readJsonCapped(new Request("https://fn/x", { method: "POST" })), undefined);
});
