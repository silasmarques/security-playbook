---
owasp: [A04]
last-review: 2026-11-10
sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
---

# Criptografia e Proteção de Dados

> Criptografia errada parece criptografia certa até o dia do incidente. Aqui só entram primitivas padrão, com parâmetros corretos — nada caseiro. Os exemplos usam a Web Crypto API (`crypto.subtle`), disponível em navegadores, Deno, Node e Bun.

## Regras

- **R1 — NEVER** inventar, compor ou "adaptar" criptografia própria. Usar Web Crypto API (`crypto.subtle`) com primitivas estabelecidas. Não existe "só um XOR para ofuscar".
- **R2 — MUST** dados sensíveis at-rest: **AES-256-GCM** com IV de 12 bytes único por operação (`crypto.getRandomValues`) e auth tag verificada na descriptografia. Reutilizar IV no GCM quebra a cifra inteira.
- **R3 — MUST** chaves vêm de env/secret manager (`Deno.env.get`), nunca de código ou de tabela do banco. Quem lê o repo ou o banco não pode obter a chave.
- **R4 — MUST** distinguir hash de criptografia: senha → hash irreversível (argon2id/bcrypt — em prática, delegar ao provedor de auth, ver `authentication.md` R1); dado que precisa voltar (token de terceiro, chave BYOK) → AES-GCM. **NEVER** "criptografar" senha nem "hashear" o que precisa ser recuperado.
- **R5 — MUST** aleatoriedade de segurança só com CSPRNG: `crypto.getRandomValues` / `crypto.randomUUID`. **NEVER** `Math.random()` para token, ID de sessão, código de verificação ou IV.
- **R6 — MUST** comparações de segredo (HMAC, assinaturas, tokens) em tempo constante. `===` retorna mais rápido quando o prefixo difere — é oráculo de timing. Para HMAC, usar a verificação da própria biblioteca de cripto (`crypto.subtle.verify`).
- **R7 — MUST** TLS em todo tráfego, sem exceção "é interno". E PII: coletar o mínimo, mascarar em logs (`logging-monitoring.md` R2).
- **R8 — MUST** versionar o formato do dado cifrado **e** identificar a chave usada (`formato.idDaChave.dados`). Sem o id da chave não existe rotação: trocar a chave exigiria decifrar e recifrar tudo de uma vez. Fallback de formato legado é removido assim que a migração termina.
- **R9 — MUST** chave de criptografia é material aleatório de 256 bits (`openssl rand -base64 32`), não senha. Tamanho errado **falha o boot**. Derivação por KDF (PBKDF2/argon2) é para quando a origem é senha humana — e aí com salt aleatório por registro.
- **R10 — MUST** amarrar o dado cifrado ao seu lugar com dado autenticado adicional (AAD): `user:<id>`, `tabela:coluna`. Sem isso, quem escreve no banco copia o ciphertext de um registro para outro e o sistema decifra como se fosse legítimo.

## Padrões prontos

### P1 — Cifra AES-256-GCM com rotação de chave e contexto

<!-- kit: kit/web/crypto.ts#cipher -->
```typescript
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
```

<!-- ilustrativo -->
```typescript
// Boot: as chaves vêm de env. Rotação = acrescentar k2, apontar `current` para
// ela e recifrar os registros em que needsRotation() for true.
const cipher = await createCipher({
  keys: { k1: mustGetEnv("DATA_KEY_K1") },
  current: "k1",
});
const stored = await cipher.encrypt(apiKey, `byok:${user.id}`);
```

> Migrando de um formato antigo (ex.: `aes256gcm:` com chave derivada por PBKDF2): manter o decifrador antigo **só** no script de migração, recifrar tudo no formato novo e apagar o código legado. Não deixar os dois caminhos vivos em produção.

### P2 — HMAC com verificação em tempo constante

<!-- kit: kit/web/crypto.ts#hmac -->
```typescript
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
```

### P3 — Payload assinado com expiração (state de OAuth, link de ação)

<!-- kit: kit/web/crypto.ts#signedPayload -->
```typescript
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
```

### P4 — Token opaco com CSPRNG

<!-- kit: kit/web/crypto.ts#opaqueToken -->
```typescript
/** Token opaco de 256 bits (reset, convite, API). Guardar no banco só o HASH
 *  (`sha256Hex`) — quem lê o banco não ganha tokens válidos. */
export function generateOpaqueToken(): string {
  return toBase64Url(crypto.getRandomValues(new Uint8Array(32)));
}

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
```

## Anti-padrões

```typescript
// ❌ NUNCA: IV fixo ou reutilizado no GCM [viola R2]
const iv = new Uint8Array(12); // zeros — duas mensagens com a mesma chave+IV
                               // vazam o XOR dos plaintexts e quebram o auth tag

// ❌ NUNCA: Math.random para material de segurança [viola R5]
const token = Math.random().toString(36).slice(2); // previsível, ~52 bits fracos

// ❌ NUNCA: comparação direta de assinatura [viola R6]
if (receivedHmac === expectedHmac) { /* ... */ } // oráculo de timing

// ❌ NUNCA: base64 como "criptografia" [viola R1, R4]
const stored = btoa(apiKey); // encoding ≠ encryption; é texto puro com fantasia
// (fallback legado assim deve ser migrado e REMOVIDO, não mantido para sempre)

// ❌ NUNCA: chave de criptografia no banco junto do dado [viola R3]
const { key } = await db.from("config").select("encryption_key").single();

// ❌ NUNCA: base64 de array grande com spread [quebra em produção]
btoa(String.fromCharCode(...bytes)); // RangeError acima de ~100 KB — codificar em fatias

// ❌ NUNCA: senha/frase como chave AES "via PBKDF2 com salt fixo" [viola R9]
// Salt fixo + segredo fraco = dicionário offline. Chave é aleatória, de 32 bytes.
```

## Checklist

- [ ] Nenhuma criptografia caseira no diff — só `crypto.subtle` com primitivas padrão?
- [ ] AES-GCM com IV aleatório de 12 bytes por operação?
- [ ] Chaves vindas de env, fora do código e do banco?
- [ ] Tokens/aleatoriedade com CSPRNG, nunca `Math.random()`?
- [ ] Comparações de HMAC/assinatura timing-safe?
- [ ] Payloads assinados têm expiração (anti-replay)?
- [ ] Formato cifrado versionado, com id de chave (rotação possível) e fallbacks legados com plano de remoção?
- [ ] Chave de 32 bytes aleatórios, com tamanho conferido no boot?
- [ ] Dado cifrado amarrado ao dono/lugar por contexto (AAD)?
