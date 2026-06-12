---
owasp: [A02]
last-review: 2026-06-11
sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
  - https://supabase.com/docs/guides/functions/secrets
  - https://vite.dev/guide/env-and-mode
---

# Secrets e Configuração Segura

> Onde moram as chaves, o que pode ir para o bundle, e como produção difere de dev. Security Misconfiguration (A02) subiu para o 2º lugar da OWASP em 2025 — a maioria dos vazamentos não é exploit sofisticado, é configuração errada.

## Regras

- **R1 — NEVER** commitar secrets (chaves de API, tokens, connection strings, certificados). `.env*` entra no `.gitignore` ANTES do primeiro commit. Se um secret vazou no histórico: **ROTACIONAR imediatamente** — remover do histórico não basta, considere-o comprometido.
- **R2 — MUST** separar secrets por ambiente (dev/staging/prod). A mesma chave em dev e prod transforma qualquer vazamento de dev em incidente de prod.
- **R3 — NEVER** colocar `service_role` key — ou qualquer credencial administrativa — em código frontend. No Vite, **tudo com prefixo `VITE_` vai para o bundle público**; presuma que qualquer um lê.
- **R4 — MUST** menor privilégio por credencial: escopo mínimo, expiração quando suportado, uma chave por integração (revogar uma não derruba as outras).
- **R5 — MUST** produção configurada explicitamente: debug/verbose OFF, security headers ON, CORS com origens nomeadas, mensagens de erro genéricas.
- **R6 — NEVER** `Access-Control-Allow-Origin: *` em endpoint autenticado — e a combinação `*` + `Allow-Credentials: true` é inválida e perigosa.
- **R7 — MUST** manter inventário de onde cada secret vive (Vercel env, Supabase secrets, GitHub secrets) e como rotacionar. Rotação que ninguém sabe fazer é rotação que não acontece.

## Padrões prontos

### P1 — Onde mora cada tipo de secret (stack Vercel + Supabase)

| Tipo | Onde | Como definir | Quem lê |
|---|---|---|---|
| Config pública do frontend (URL do Supabase, anon key) | Env do Vercel com prefixo `VITE_` | Dashboard Vercel → Environment Variables | Bundle público — **anon key é pública por design; a proteção é RLS** |
| Secrets de Edge Functions (chaves de IA, `ENCRYPTION_KEY`, HMAC) | Supabase secrets | `supabase secrets set NOME=valor` | `Deno.env.get("NOME")` só no servidor |
| Secrets de CI (deploy tokens) | GitHub Actions secrets | Repo → Settings → Secrets | `${{ secrets.NOME }}` só nos jobs que precisam |
| `service_role` key | **Nunca no frontend, nunca no repo** | Já existe no painel Supabase | Apenas Edge Functions/backend, via env |
| Dev local | `.env.local` (gitignored) | manual | só a máquina do dev |

### P2 — Security headers de referência (toda resposta HTML; APIs: os 3 primeiros)

```typescript
export const SECURITY_HEADERS = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Content-Security-Policy": "default-src 'self'; frame-ancestors 'none'",
  "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
} as const;
// No Vercel: ver core/frontend-security.md P3 (vercel.json).
// Em Edge Functions: mesclar nos headers de TODA resposta.
```

### P3 — Scan rápido de secrets antes do commit

```powershell
# Olhar o que está staged antes de commitar:
git diff --cached | Select-String -Pattern 'api[_-]?key|secret|password|token|BEGIN.*PRIVATE KEY' -CaseSensitive:$false
# Saída esperada: vazia. Qualquer match → inspecionar antes de prosseguir.
```

```gitignore
# .gitignore mínimo de segurança — primeiro commit do projeto
.env
.env.*
!.env.example
*.pem
*.key
```

> `.env.example` versionado com os NOMES das variáveis (sem valores) documenta a
> configuração sem expor nada.

## Anti-padrões

```typescript
// ❌ NUNCA: secret hardcoded — vai para o git e para o bundle [viola R1]
const GEMINI_KEY = "AIzaSyD...";

// ❌ NUNCA: credencial administrativa exposta ao bundle [viola R3]
// .env: VITE_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOi...
// Prefixo VITE_ = público. service_role bypassa RLS: é o banco inteiro aberto.

// ❌ NUNCA: fallback de secret no código [viola R1, R2]
const key = Deno.env.get("ENCRYPTION_KEY") ?? "dev-key-123";
// Env faltando em prod → roda silenciosamente com chave conhecida.

// ❌ NUNCA: CORS aberto com credenciais [viola R6]
headers.set("Access-Control-Allow-Origin", "*");
headers.set("Access-Control-Allow-Credentials", "true");
```

## Checklist

- [ ] Diff sem secrets (scan do P3 rodado e vazio)?
- [ ] `.env*` no `.gitignore` e `.env.example` sem valores reais?
- [ ] Nenhuma variável `VITE_` contém credencial não-pública?
- [ ] Secret novo registrado no inventário (P1) no ambiente certo?
- [ ] Sem fallback hardcoded para env ausente — falhar rápido em vez de degradar?
- [ ] CORS do endpoint novo usa allowlist de origens?
- [ ] Security headers presentes nas respostas?
