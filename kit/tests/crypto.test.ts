import { assert, assertEquals, assertFalse, assertNotEquals, assertRejects } from "@std/assert";
import {
  createCipher,
  fromBase64Url,
  generateOpaqueToken,
  hmacSign,
  hmacVerify,
  sha256Hex,
  signPayload,
  timingSafeEqual,
  toBase64Url,
  verifyPayload,
} from "../web/crypto.ts";

const key = () => btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32))));
const K1 = key(), K2 = key();
const SECRET = "segredo-hmac-com-pelo-menos-32-bytes-ok!";

Deno.test("cipher: ida e volta, inclusive unicode e vazio", async () => {
  const c = await createCipher({ keys: { k1: K1 }, current: "k1" });
  for (const pt of ["sk-live-abc123", "", "ação ✓ 日本語 🔐"]) {
    assertEquals(await c.decrypt(await c.encrypt(pt)), pt);
  }
});

Deno.test("cipher: payload de 1 MB não estoura a pilha (regressão do btoa com spread)", async () => {
  const c = await createCipher({ keys: { k1: K1 }, current: "k1" });
  const big = "x".repeat(1_000_000);
  assertEquals((await c.decrypt(await c.encrypt(big))).length, big.length);
});

Deno.test("cipher: IV único — o mesmo texto cifra diferente a cada vez", async () => {
  const c = await createCipher({ keys: { k1: K1 }, current: "k1" });
  const seen = new Set<string>();
  for (let i = 0; i < 50; i++) seen.add(await c.encrypt("mesmo texto"));
  assertEquals(seen.size, 50);
});

Deno.test("cipher: um bit adulterado → decrypt lança (auth tag)", async () => {
  const c = await createCipher({ keys: { k1: K1 }, current: "k1" });
  const stored = await c.encrypt("valor");
  const [f, k, p] = stored.split(".") as [string, string, string];
  const blob = fromBase64Url(p);
  blob[blob.length - 1]! ^= 1;
  await assertRejects(() => c.decrypt(`${f}.${k}.${toBase64Url(blob)}`));
});

Deno.test("cipher: contexto (AAD) amarra o dado — ciphertext de A não decifra como B", async () => {
  const c = await createCipher({ keys: { k1: K1 }, current: "k1" });
  const stored = await c.encrypt("chave-do-usuario-A", "user:A");
  assertEquals(await c.decrypt(stored, "user:A"), "chave-do-usuario-A");
  await assertRejects(() => c.decrypt(stored, "user:B"));
  await assertRejects(() => c.decrypt(stored));
});

Deno.test("cipher: rotação — chave antiga ainda lê, nova cifra, needsRotation acusa", async () => {
  const antigo = await createCipher({ keys: { k1: K1 }, current: "k1" });
  const stored = await antigo.encrypt("dado legado");
  const rotacionado = await createCipher({ keys: { k1: K1, k2: K2 }, current: "k2" });
  assertEquals(await rotacionado.decrypt(stored), "dado legado");
  assert(rotacionado.needsRotation(stored));
  const novo = await rotacionado.encrypt("dado legado");
  assert(novo.startsWith("aesgcm1.k2."));
  assertFalse(rotacionado.needsRotation(novo));
  // quem só tem a chave antiga não lê o novo
  await assertRejects(() => antigo.decrypt(novo));
});

Deno.test("cipher: formato desconhecido, base64 puro e texto claro são rejeitados", async () => {
  const c = await createCipher({ keys: { k1: K1 }, current: "k1" });
  for (const bad of ["", "texto-claro", btoa("sk-live-abc"), "aes256gcm:AAAA", "aesgcm1.k1", "aesgcm1.k9.AAAA", "aesgcm2.k1.AAAA", "aesgcm1.k1.AAAA.extra"]) {
    await assertRejects(() => c.decrypt(bad), Error, undefined, `aceitou: ${bad}`);
  }
});

Deno.test("cipher: chave de tamanho errado ou config inconsistente falha o boot", async () => {
  await assertRejects(() => createCipher({ keys: { k1: btoa("curta") }, current: "k1" }));
  // 16 e 24 bytes são chaves AES válidas (128/192 bits) — a norma exige 256, e só 256
  for (const n of [16, 24, 33, 64]) {
    const k = btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(n))));
    await assertRejects(() => createCipher({ keys: { k1: k }, current: "k1" }), Error, "32 bytes", `aceitou chave de ${n} bytes`);
  }
  await assertRejects(() => createCipher({ keys: { k1: "não é base64!!" }, current: "k1" }));
  await assertRejects(() => createCipher({ keys: { k1: K1 }, current: "k2" }));
  await assertRejects(() => createCipher({ keys: { "K 1": K1 }, current: "K 1" }));
});

Deno.test("hmac: verifica o que assinou; rejeita payload, assinatura ou segredo diferentes", async () => {
  const sig = await hmacSign("corpo-do-webhook", SECRET);
  assert(await hmacVerify("corpo-do-webhook", sig, SECRET));
  assertFalse(await hmacVerify("corpo-do-webhook!", sig, SECRET));
  assertFalse(await hmacVerify("corpo-do-webhook", sig.slice(0, -2) + "AA", SECRET));
  assertFalse(await hmacVerify("corpo-do-webhook", sig, SECRET + "x"));
  assertFalse(await hmacVerify("corpo-do-webhook", "", SECRET));
  assertFalse(await hmacVerify("corpo-do-webhook", "não é base64 !!!", SECRET));
});

Deno.test("hmac: segredo curto é recusado", async () => {
  await assertRejects(() => hmacSign("x", "curto"));
});

Deno.test("timingSafeEqual: igualdade exata, inclusive tamanhos diferentes", () => {
  assert(timingSafeEqual("abc", "abc"));
  assertFalse(timingSafeEqual("abc", "abd"));
  assertFalse(timingSafeEqual("abc", "abcd"));
  assertFalse(timingSafeEqual("", "a"));
  assert(timingSafeEqual("", ""));
});

Deno.test("payload assinado: válido dentro da janela; adulterado, expirado e 'do futuro' → null", async () => {
  const t0 = 1_700_000_000_000;
  const token = await signPayload({ userId: "u1", action: "oauth" }, SECRET, t0);
  const ok = await verifyPayload(token, SECRET, { now: t0 + 60_000 });
  assertEquals(ok?.userId, "u1");

  assertEquals(await verifyPayload(token, SECRET, { now: t0 + 11 * 60_000 }), null);            // replay
  assertEquals(await verifyPayload(token, SECRET, { now: t0 - 5 * 60_000 }), null);             // futuro
  assertEquals(await verifyPayload(token, SECRET + "x", { now: t0 }), null);                    // segredo errado

  const [body, sig] = token.split(".") as [string, string];
  const forged = toBase64Url(new TextEncoder().encode(JSON.stringify({ userId: "admin", iat: t0 })));
  assertEquals(await verifyPayload(`${forged}.${sig}`, SECRET, { now: t0 }), null);             // corpo trocado
  assertEquals(await verifyPayload(body, SECRET, { now: t0 }), null);                           // sem assinatura
  assertEquals(await verifyPayload(`${body}.${sig}.x`, SECRET, { now: t0 }), null);
});

Deno.test("token opaco: 256 bits, base64url, sem repetição; hash estável", async () => {
  const tokens = new Set(Array.from({ length: 200 }, generateOpaqueToken));
  assertEquals(tokens.size, 200);
  for (const t of tokens) { assert(/^[A-Za-z0-9_-]{43}$/.test(t)); break; }
  assertEquals(await sha256Hex("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  assertNotEquals(await sha256Hex("abc"), await sha256Hex("abd"));
});
