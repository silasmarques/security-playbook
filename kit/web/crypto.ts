// Criptografia com Web Crypto: AES-256-GCM com rotação de chave, HMAC com
// verificação em tempo constante, payload assinado com expiração e token opaco.
// Norma: core/crypto-data-protection.md. Testes: kit/tests/crypto.test.ts.

const enc = new TextEncoder();
const dec = new TextDecoder();

// --- base64 sem `String.fromCharCode(...bytes)`: o spread estoura a pilha em
//     payloads de ~100 KB+ (medido). Aqui vai em fatias. ---
export function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i += 0x8000) {
    bin += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(text: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error("base64url inválido");
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

// #region cipher
const FORMAT = "aesgcm1"; // versão do FORMATO — muda se o algoritmo mudar
const IV_BYTES = 12;      // 96 bits, o recomendado para GCM

export interface CipherConfig {
  /** id → chave de 32 bytes em base64 (gerar: `openssl rand -base64 32`). */
  keys: Record<string, string>;
  /** id da chave usada para CIFRAR. As demais só decifram (rotação). */
  current: string;
}

/** Cifra/decifra com AES-256-GCM. Saída: `aesgcm1.<keyId>.<base64url(iv|ct|tag)>`.
 *  O keyId no formato é o que torna a ROTAÇÃO possível: chave nova entra como
 *  `current`, a antiga fica só para ler, e os registros são recifrados aos poucos. */
export async function createCipher(config: CipherConfig) {
  const keys = new Map<string, CryptoKey>();
  for (const [id, b64] of Object.entries(config.keys)) {
    if (!/^[a-z0-9]{1,16}$/.test(id)) throw new Error(`keyId inválido: ${id}`);
    let raw: Uint8Array<ArrayBuffer>;
    try { raw = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0)); } catch { throw new Error(`chave ${id}: base64 inválido`); }
    // Chave de tamanho errado FALHA o boot — nunca "deriva um jeito" de usar senha fraca.
    if (raw.length !== 32) throw new Error(`chave ${id}: esperados 32 bytes, vieram ${raw.length}`);
    keys.set(id, await crypto.subtle.importKey("raw", raw, "AES-GCM", false, ["encrypt", "decrypt"]));
  }
  if (!keys.has(config.current)) throw new Error("chave `current` não está em `keys`");

  return {
    /** `context` (AAD) amarra o dado ao seu lugar — ex.: `user:${userId}`. Um
     *  ciphertext copiado para o registro de OUTRO usuário não decifra. */
    async encrypt(plaintext: string, context = ""): Promise<string> {
      const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES)); // ÚNICO por operação
      const ct = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv, additionalData: enc.encode(context) },
        keys.get(config.current)!, enc.encode(plaintext));
      const blob = new Uint8Array(IV_BYTES + ct.byteLength);
      blob.set(iv, 0);
      blob.set(new Uint8Array(ct), IV_BYTES);
      return `${FORMAT}.${config.current}.${toBase64Url(blob)}`;
    },

    async decrypt(stored: string, context = ""): Promise<string> {
      const [format, keyId, payload, ...rest] = stored.split(".");
      if (format !== FORMAT || !keyId || !payload || rest.length > 0) throw new Error("formato cifrado desconhecido");
      const key = keys.get(keyId);
      if (!key) throw new Error(`chave ${keyId} não disponível`);
      const blob = fromBase64Url(payload);
      if (blob.length <= IV_BYTES) throw new Error("ciphertext truncado");
      // GCM lança se o tag não bater (dado adulterado, chave errada, contexto errado).
      // NÃO capturar para "tentar outro formato": é fail closed.
      const pt = await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: blob.subarray(0, IV_BYTES), additionalData: enc.encode(context) },
        key, blob.subarray(IV_BYTES));
      return dec.decode(pt);
    },

    /** true se o registro foi cifrado com chave antiga → recifrar e regravar. */
    needsRotation(stored: string): boolean {
      return stored.split(".")[1] !== config.current;
    },
  };
}
// #endregion cipher

// #region hmac
async function hmacKey(secret: string, usage: KeyUsage): Promise<CryptoKey> {
  if (enc.encode(secret).length < 32) throw new Error("segredo HMAC curto demais (mínimo 32 bytes)");
  return crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, [usage]);
}

export async function hmacSign(payload: string, secret: string): Promise<string> {
  const sig = await crypto.subtle.sign("HMAC", await hmacKey(secret, "sign"), enc.encode(payload));
  return toBase64Url(new Uint8Array(sig));
}

/** Verifica a assinatura com `crypto.subtle.verify` — a comparação fica dentro
 *  da implementação de cripto, não em `===` (oráculo de timing). */
export async function hmacVerify(payload: string, signature: string, secret: string): Promise<boolean> {
  let sig: Uint8Array<ArrayBuffer>;
  try { sig = fromBase64Url(signature); } catch { return false; }
  return crypto.subtle.verify("HMAC", await hmacKey(secret, "verify"), sig, enc.encode(payload));
}

/** Para comparar dois segredos que NÃO são HMAC (ex.: token opaco vs. o
 *  guardado). Percorre tudo sempre, sem retorno antecipado. */
export function timingSafeEqual(a: string, b: string): boolean {
  const aB = enc.encode(a), bB = enc.encode(b);
  let diff = aB.length ^ bB.length;
  for (let i = 0; i < Math.max(aB.length, bB.length); i++) diff |= (aB[i] ?? 0) ^ (bB[i] ?? 0);
  return diff === 0;
}
// #endregion hmac

// #region signedPayload
/** `base64url(JSON).assinatura`, com `iat` dentro do que é assinado. Uso típico:
 *  `state` de OAuth, link de ação com validade. */
export async function signPayload(data: Record<string, unknown>, secret: string, now = Date.now()): Promise<string> {
  const body = toBase64Url(enc.encode(JSON.stringify({ ...data, iat: now })));
  return `${body}.${await hmacSign(body, secret)}`;
}

export async function verifyPayload(
  token: string,
  secret: string,
  opts: { maxAgeMs?: number; skewMs?: number; now?: number } = {},
): Promise<Record<string, unknown> | null> {
  const [body, sig, ...rest] = token.split(".");
  if (!body || !sig || rest.length > 0) return null;
  if (!(await hmacVerify(body, sig, secret))) return null;   // assinatura ANTES de ler o conteúdo
  let data: unknown;
  try { data = JSON.parse(dec.decode(fromBase64Url(body))); } catch { return null; }
  if (typeof data !== "object" || data === null) return null;
  const iat = (data as Record<string, unknown>).iat;
  if (typeof iat !== "number") return null;
  const now = opts.now ?? Date.now();
  if (now - iat > (opts.maxAgeMs ?? 10 * 60_000)) return null; // velho demais → replay
  if (iat - now > (opts.skewMs ?? 60_000)) return null;        // "do futuro" → relógio forjado
  return data as Record<string, unknown>;
}
// #endregion signedPayload

// #region opaqueToken
/** Token opaco de 256 bits (reset, convite, API). Guardar no banco só o HASH
 *  (`sha256Hex`) — quem lê o banco não ganha tokens válidos. */
export function generateOpaqueToken(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
// #endregion opaqueToken
