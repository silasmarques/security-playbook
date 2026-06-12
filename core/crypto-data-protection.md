---
owasp: [A04]
last-review: 2026-06-11
sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
---

# Criptografia e Proteção de Dados

> Criptografia errada parece criptografia certa até o dia do incidente. Aqui só entram primitivas padrão da Web Crypto API, com parâmetros corretos — nada caseiro.

## Regras

- **R1 — NEVER** inventar, compor ou "adaptar" criptografia própria. Usar Web Crypto API (`crypto.subtle`) com primitivas estabelecidas. Não existe "só um XOR para ofuscar".
- **R2 — MUST** dados sensíveis at-rest: **AES-256-GCM** com IV de 12 bytes único por operação (`crypto.getRandomValues`) e auth tag verificada na descriptografia. Reutilizar IV no GCM quebra a cifra inteira.
- **R3 — MUST** chaves vêm de env/secret manager (`Deno.env.get`), nunca de código ou de tabela do banco. Quem lê o repo ou o banco não pode obter a chave.
- **R4 — MUST** distinguir hash de criptografia: senha → hash irreversível (argon2id/bcrypt — em prática, delegar ao provedor de auth, ver `authentication.md` R1); dado que precisa voltar (token de terceiro, chave BYOK) → AES-GCM. **NEVER** "criptografar" senha nem "hashear" o que precisa ser recuperado.
- **R5 — MUST** aleatoriedade de segurança só com CSPRNG: `crypto.getRandomValues` / `crypto.randomUUID`. **NEVER** `Math.random()` para token, ID de sessão, código de verificação ou IV.
- **R6 — MUST** comparações de segredo (HMAC, assinaturas, tokens) em tempo constante. `===` retorna mais rápido quando o prefixo difere — é oráculo de timing.
- **R7 — MUST** TLS em todo tráfego, sem exceção "é interno". E PII: coletar o mínimo, mascarar em logs (`logging-monitoring.md` R2).
- **R8 — MUST** versionar o formato do dado cifrado (prefixo tipo `aes256gcm:`) para permitir migração de algoritmo sem ambiguidade — e remover fallbacks de formato legado inseguro assim que a migração terminar.

## Padrões prontos

### P1 — Encrypt/decrypt AES-256-GCM (Web Crypto, Deno/browser)

```typescript
const ALGORITHM = "AES-GCM";
const IV_LENGTH = 12;       // 96 bits — recomendado para GCM
const TAG_LENGTH = 128;     // bits — auth tag completa

async function deriveKey(secret: string): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const material = await crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "PBKDF2" }, false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt: enc.encode("app-salt-v1"), iterations: 100_000, hash: "SHA-256" },
    material, { name: ALGORITHM, length: 256 }, false, ["encrypt", "decrypt"]);
  // Salt fixo é aceitável AQUI porque o secret vem de env com alta entropia
  // (não é senha de usuário). Para derivar de senha humana: salt aleatório
  // por registro, armazenado junto ao ciphertext.
}

export async function encryptSecret(plaintext: string, secret: string): Promise<string> {
  const key = await deriveKey(secret);
  const iv = crypto.getRandomValues(new Uint8Array(IV_LENGTH)); // ÚNICO por operação
  const ciphertext = await crypto.subtle.encrypt(
    { name: ALGORITHM, iv, tagLength: TAG_LENGTH }, key, new TextEncoder().encode(plaintext));
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  return "aes256gcm:" + btoa(String.fromCharCode(...combined)); // formato versionado
}

export async function decryptSecret(encrypted: string, secret: string): Promise<string> {
  if (!encrypted.startsWith("aes256gcm:")) throw new Error("formato desconhecido");
  const combined = Uint8Array.from(atob(encrypted.slice(10)), (c) => c.charCodeAt(0));
  const key = await deriveKey(secret);
  const decrypted = await crypto.subtle.decrypt(
    { name: ALGORITHM, iv: combined.slice(0, IV_LENGTH), tagLength: TAG_LENGTH },
    key, combined.slice(IV_LENGTH)); // GCM lança se o auth tag não bater — não engolir
  return new TextDecoder().decode(decrypted);
}
```

### P2 — Payload assinado com HMAC e verificação timing-safe (state OAuth, webhooks)

```typescript
async function hmacSign(payload: string, secret: string): Promise<string> {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload));
  return base64UrlEncode(new Uint8Array(sig));
}

// Criar: `${base64url(JSON)}.${hmac}` com timestamp dentro do payload.
// Verificar: recalcular o HMAC e comparar em TEMPO CONSTANTE + checar expiração:
function timingSafeEqual(a: string, b: string): boolean {
  const aB = new TextEncoder().encode(a);
  const bB = new TextEncoder().encode(b);
  let diff = aB.length ^ bB.length;
  for (let i = 0; i < Math.max(aB.length, bB.length); i++) {
    diff |= (aB[i] ?? 0) ^ (bB[i] ?? 0); // percorre TUDO sempre — sem early return
  }
  return diff === 0;
}
// Expiração: rejeitar payload.timestamp mais antigo que 10 min (replay) e
// mais "futuro" que 60s (clock skew).
```

### P3 — Token opaco com CSPRNG

```typescript
function generateOpaqueToken(): string {
  const bytes = crypto.getRandomValues(new Uint8Array(32)); // 256 bits de entropia
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, ""); // base64url
}
// Para IDs não-secretos, crypto.randomUUID() basta.
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
```

## Checklist

- [ ] Nenhuma criptografia caseira no diff — só `crypto.subtle` com primitivas padrão?
- [ ] AES-GCM com IV aleatório de 12 bytes por operação?
- [ ] Chaves vindas de env, fora do código e do banco?
- [ ] Tokens/aleatoriedade com CSPRNG, nunca `Math.random()`?
- [ ] Comparações de HMAC/assinatura timing-safe?
- [ ] Payloads assinados têm expiração (anti-replay)?
- [ ] Formato cifrado versionado e fallbacks legados com plano de remoção?
