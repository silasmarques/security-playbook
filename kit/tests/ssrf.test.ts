import { assert, assertEquals, assertRejects } from "@std/assert";
import {
  isBlockedIp,
  OutboundBlockedError,
  readBodyCapped,
  safeFetch,
  validateOutboundUrl,
} from "../web/ssrf.ts";

const BLOQUEADAS = [
  // metadata de nuvem e loopback, em todas as formas
  "http://169.254.169.254/latest/meta-data/",
  "http://127.0.0.1:5432/",
  "http://2130706433/",          // decimal
  "http://0x7f000001/",          // hex
  "http://0177.0.0.1/",          // octal
  "http://127.1/",               // comprimida
  "http://127.0.0.1./",          // ponto final
  "http://0.0.0.0/",
  // privadas
  "http://10.0.0.5/", "http://172.16.0.1/", "http://172.31.255.255/", "http://192.168.1.1/",
  "http://100.64.0.1/",          // CGNAT
  "http://224.0.0.1/", "http://255.255.255.255/",
  // IPv6
  "http://[::1]/", "http://[::]/",
  "http://[::ffff:127.0.0.1]/",  // IPv4-mapped
  "http://[::ffff:a9fe:a9fe]/",  // IPv4-mapped de 169.254.169.254, em hex
  "http://[64:ff9b::7f00:1]/",   // NAT64 → 127.0.0.1
  "http://[2002:7f00:1::]/",     // 6to4 → 127.0.0.1
  "http://[fc00::1]/", "http://[fd12:3456::1]/", "http://[fe80::1]/", "http://[ff02::1]/",
  // hostnames internos
  "http://localhost/", "http://LOCALHOST/", "http://foo.localhost/",
  "http://metadata.google.internal/", "http://db.internal/", "http://printer.local/",
  "http://intranet/",            // sem ponto: nome de rede interna
  "https://abc.supabase.co/rest/v1/",
  // protocolo e forma
  "file:///etc/passwd", "gopher://example.com/", "ftp://example.com/", "data:text/plain,oi",
  "javascript:alert(1)",
  "http://user:senha@example.com/",
  "", "nao-e-url",
];

const PERMITIDAS = [
  "https://example.com/",
  "http://example.com:8080/caminho?q=1",
  "https://8.8.8.8/",
  "https://172.15.0.1/",   // logo abaixo de 172.16/12
  "https://172.32.0.1/",   // logo acima
  "https://[2606:4700:4700::1111]/",
  "https://[::ffff:8.8.8.8]/",
];

for (const u of BLOQUEADAS) {
  Deno.test(`SSRF bloqueia: ${u || "(vazia)"}`, () => {
    assertEquals(validateOutboundUrl(u).ok, false);
  });
}
for (const u of PERMITIDAS) {
  Deno.test(`SSRF permite destino público: ${u}`, () => {
    assertEquals(validateOutboundUrl(u).ok, true);
  });
}

Deno.test("SSRF: tipos errados e URL gigante são negados", () => {
  for (const v of [null, undefined, 42, {}, ["http://example.com"], "http://example.com/" + "a".repeat(9000)]) {
    assertEquals(validateOutboundUrl(v).ok, false);
  }
});

Deno.test("SSRF: allowlist nega tudo que não está nela, inclusive destino público", () => {
  const policy = { allowedHosts: ["api.exemplo.com", "*.atlassian.net"] };
  assertEquals(validateOutboundUrl("https://api.exemplo.com/x", policy).ok, true);
  assertEquals(validateOutboundUrl("https://time.atlassian.net/x", policy).ok, true);
  assertEquals(validateOutboundUrl("https://atlassian.net/x", policy).ok, false);       // curinga exige subdomínio
  assertEquals(validateOutboundUrl("https://evilatlassian.net/x", policy).ok, false);   // sufixo sem ponto
  assertEquals(validateOutboundUrl("https://api.exemplo.com.evil.com/", policy).ok, false);
  assertEquals(validateOutboundUrl("https://example.com/", policy).ok, false);
});

Deno.test("isBlockedIp: entrada que não é IP é negada (fail closed)", () => {
  assert(isBlockedIp("não-é-ip"));
  assert(isBlockedIp("10.1.2.3"));
  assert(isBlockedIp("fd00::1"));
  assert(!isBlockedIp("1.1.1.1"));
  assert(!isBlockedIp("2606:4700:4700::1111"));
});

// --- safeFetch com fetch falso: prova a revalidação por hop ---
function fakeFetch(routes: Record<string, () => Response>): { impl: typeof fetch; calls: string[] } {
  const calls: string[] = [];
  const impl = ((input: URL | RequestInfo) => {
    const url = String(input instanceof Request ? input.url : input);
    calls.push(url);
    const route = routes[url];
    return Promise.resolve(route ? route() : new Response("não mapeada", { status: 404 }));
  }) as typeof fetch;
  return { impl, calls };
}
const redirect = (to: string) => () => new Response(null, { status: 302, headers: { location: to } });

Deno.test("safeFetch: redirect para IP de metadata é bloqueado e NUNCA é requisitado", async () => {
  const { impl, calls } = fakeFetch({
    "https://example.com/": redirect("http://169.254.169.254/latest/meta-data/"),
  });
  await assertRejects(() => safeFetch("https://example.com/", { fetchImpl: impl }), OutboundBlockedError);
  assertEquals(calls, ["https://example.com/"]);
});

Deno.test("safeFetch: bloqueio no 2º hop de uma cadeia", async () => {
  const { impl, calls } = fakeFetch({
    "https://a.example.com/": redirect("https://b.example.com/"),
    "https://b.example.com/": redirect("http://[::ffff:10.0.0.1]/"),
  });
  await assertRejects(() => safeFetch("https://a.example.com/", { fetchImpl: impl }), OutboundBlockedError);
  assertEquals(calls.length, 2);
});

Deno.test("safeFetch: segue redirect público (inclusive relativo) e devolve o final", async () => {
  const { impl } = fakeFetch({
    "https://example.com/": redirect("/novo"),
    "https://example.com/novo": () => new Response("conteúdo"),
  });
  const res = await safeFetch("https://example.com/", { fetchImpl: impl });
  assertEquals(await res.text(), "conteúdo");
});

Deno.test("safeFetch: laço de redirect estoura o teto", async () => {
  const { impl, calls } = fakeFetch({ "https://example.com/": redirect("https://example.com/") });
  await assertRejects(() => safeFetch("https://example.com/", { fetchImpl: impl, maxRedirects: 2 }), OutboundBlockedError);
  assertEquals(calls.length, 3);
});

Deno.test("safeFetch: URL inicial interna não gera requisição alguma", async () => {
  const { impl, calls } = fakeFetch({});
  await assertRejects(() => safeFetch("http://127.0.0.1/", { fetchImpl: impl }), OutboundBlockedError);
  assertEquals(calls.length, 0);
});

Deno.test("safeFetch: resolveHost bloqueia hostname público que resolve para IP privado", async () => {
  const { impl, calls } = fakeFetch({ "https://rebind.example.com/": () => new Response("x") });
  await assertRejects(
    () => safeFetch("https://rebind.example.com/", { fetchImpl: impl, resolveHost: () => Promise.resolve(["10.0.0.7"]) }),
    OutboundBlockedError,
  );
  assertEquals(calls.length, 0);
  const ok = await safeFetch("https://rebind.example.com/", { fetchImpl: impl, resolveHost: () => Promise.resolve(["93.184.216.34"]) });
  assertEquals(ok.status, 200);
});

Deno.test("readBodyCapped: corta resposta acima do teto, com e sem content-length", async () => {
  const grande = "x".repeat(5000);
  await assertRejects(() => readBodyCapped(new Response(grande, { headers: { "content-length": "5000" } }), 1000), OutboundBlockedError);
  const semHeader = new Response(new ReadableStream({
    start(c) { c.enqueue(new TextEncoder().encode(grande)); c.close(); },
  }));
  await assertRejects(() => readBodyCapped(semHeader, 1000), OutboundBlockedError);
  assertEquals((await readBodyCapped(new Response("ok"), 1000)).byteLength, 2);
});
