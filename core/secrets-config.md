---
owasp: [A02]
last-review: 2026-11-10
sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
  - https://supabase.com/docs/guides/functions/secrets
  - https://vite.dev/guide/env-and-mode
  - https://github.com/gitleaks/gitleaks-action
  - https://supabase.com/docs/guides/api/api-keys
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Access-Control-Allow-Origin
---

# Secrets e Configuração Segura

> Onde moram as chaves, o que pode ir para o bundle, e como produção difere de dev. Security Misconfiguration (A02) subiu para o 2º lugar da OWASP em 2025 — a maioria dos vazamentos não é exploit sofisticado, é configuração errada.

## Regras

- **R1 — NEVER** commitar secrets (chaves de API, tokens, connection strings, certificados). `.env*` entra no `.gitignore` ANTES do primeiro commit. Se um secret vazou no histórico: **ROTACIONAR imediatamente** — remover do histórico não basta, considere-o comprometido.
- **R2 — MUST** separar secrets por ambiente (dev/staging/prod). A mesma chave em dev e prod transforma qualquer vazamento de dev em incidente de prod.
- **R3 — NEVER** colocar `service_role` key — ou qualquer credencial administrativa — em código frontend. No Vite, **tudo com prefixo `VITE_` vai para o bundle público**; presuma que qualquer um lê.
- **R4 — MUST** menor privilégio por credencial: escopo mínimo, expiração quando suportado, uma chave por integração (revogar uma não derruba as outras).
- **R5 — MUST** produção configurada explicitamente: debug/verbose OFF, security headers ON, CORS com origens nomeadas, mensagens de erro genéricas.
- **R6 — NEVER** `Access-Control-Allow-Origin: *` em endpoint autenticado, nem o valor `null` (a especificação o desaconselha: qualquer página consegue produzir uma origem `null`). A combinação `*` + `Allow-Credentials: true` é inválida. Origem fora da allowlist simplesmente não recebe o header (`api-security.md` R7).
- **R7 — MUST** manter inventário de onde cada secret vive (Vercel env, Supabase secrets, GitHub secrets) e como rotacionar. Rotação que ninguém sabe fazer é rotação que não acontece.
- **R9 — MUST** segredo **insubstituível** — o que não dá para rotacionar: keystore/chave de assinatura de app, chave de criptografia de dados já gravados, seed de carteira — tem ao menos **duas cópias em lugares independentes**, e a restauração é **testada** (abrir a cópia e usar, não "ver que o arquivo está lá"). Cópia única num disco é perda garantida, só sem data marcada. Nome de pasta sincronizada não é evidência de sincronização.
- **R8 — MUST** tratar mudança em config/secret/variável de ambiente como **mudança de risco**. Para cada valor, saber se é consumido em **build-time** (embutido no artefato gerado — precisa existir no momento do build) ou em **runtime** (lido pelo processo em execução — precisa existir no ambiente de execução), e garantir que exista no **ambiente de destino** (produção/staging), não só no local. Mover, remover, renomear ou trocar a fonte de uma config é mudança de risco: verificar no ambiente/artefato real de destino antes de declarar concluído — "funciona no meu local" não é evidência. Config crítica ausente **falha o build ou o boot** — nunca inicia degradada em silêncio.

## Padrões prontos

### P1 — Onde mora cada tipo de secret (stack Vercel + Supabase)

| Tipo | Onde | Como definir | Quem lê |
|---|---|---|---|
| Config pública do frontend (URL do Supabase, publishable key `sb_publishable_...`) | Env do Vercel com prefixo `VITE_` | Dashboard Vercel → Environment Variables | Bundle público — **a publishable key é pública por design; a proteção é RLS** |
| Secrets de Edge Functions (chaves de IA, `ENCRYPTION_KEY`, HMAC) | Supabase secrets | `supabase secrets set NOME=valor` | `Deno.env.get("NOME")` só no servidor |
| Secrets de CI (deploy tokens) | GitHub Actions secrets | Repo → Settings → Secrets | `${{ secrets.NOME }}` só nos jobs que precisam |
| Secret key (`sb_secret_...`; `service_role` no modelo legado) | **Nunca no frontend, nunca no repo** | Painel Supabase → API Keys | Apenas Edge Functions/backend, via env — a secret key nova **rejeita requisições de navegador automaticamente** |
| Dev local | `.env.local` (gitignored) | manual | só a máquina do dev |

> **Migração de chaves (validado 2026-07-02):** as chaves JWT legadas (`anon`/`service_role`)
> seguem funcionando, mas a doc oficial recomenda as novas (`sb_publishable_...`/`sb_secret_...`)
> para todo projeto — em especial a secret key, pela rejeição nativa de uso em navegador.

### P2 — Security headers e leitura de env

Para respostas de API (para HTML, a CSP completa do host está em `frontend-security.md` P3):

<!-- kit: kit/web/http.ts#securityHeaders -->
```typescript
/** Headers de segurança para respostas de API (JSON). Para HTML, somar a CSP
 *  completa do host — ver core/frontend-security.md P3. */
export const API_SECURITY_HEADERS: Readonly<Record<string, string>> = {
  "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
  "X-Content-Type-Options": "nosniff",
  "Referrer-Policy": "no-referrer",
  // API não renderiza nada: negar tudo e proibir enquadramento.
  "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
  "Cache-Control": "no-store",
};
```

Config obrigatória — ausente, falha o boot:

<!-- kit: kit/web/env.ts#mustGetEnv -->
```typescript
/** Env obrigatória: ausente ou em branco LANÇA. Nunca `?? "valor-padrão"` —
 *  fallback de segredo roda em produção com chave conhecida, em silêncio. */
export function mustGetEnv(name: string, source: EnvSource = runtimeEnv): string {
  const value = source(name);
  if (value === undefined || value.trim() === "") {
    throw new Error(`variável de ambiente obrigatória ausente: ${name}`);
  }
  return value;
}
```

### P3 — Scan rápido de secrets antes do commit

```bash
# Olhar o que está staged antes de commitar (macOS/Linux/Git Bash):
git diff --cached | grep -inE 'api[_-]?key|secret|password|token|BEGIN.*PRIVATE KEY'
# Saída esperada: vazia. Qualquer linha → inspecionar antes de prosseguir.
# PowerShell: git diff --cached | Select-String -Pattern '<mesmo padrão>'
```

> Este grep é triagem rápida, com falso positivo (a palavra "token" num nome de variável) e falso negativo (chave sem palavra-chave por perto). Quem pega padrão de chave de verdade é o scanner do P4.

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

### P4 — Secret scan automatizado no CI (gitleaks)

O scan manual do P3 pega o commit atual; o CI pega o histórico e o que passou batido. Complementares — os dois, não um ou outro.

```yaml
# .github/workflows/gitleaks.yml
name: gitleaks
on: [pull_request, push, workflow_dispatch]
permissions:
  contents: read
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
        with:
          fetch-depth: 0          # histórico completo — sem isso, só varre o HEAD
      - uses: gitleaks/gitleaks-action@ff98106e4c7b2bc287b24eaf42907196329070c7 # v2.3.9
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
          # GITLEAKS_LICENSE: só exigido para organizações; conta pessoal não precisa.
```

> Achou um secret no histórico? O CI falha — mas **rotacionar** vem primeiro
> (R1): considere a chave comprometida, remover do histórico não basta.

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
- [ ] Cada variável está classificada (build-time vs runtime) e existe no ambiente de destino, não só no local?
- [ ] Mudança que altera a origem da config (mover/remover/renomear/trocar fonte) foi verificada no artefato/ambiente real de destino?
- [ ] Config crítica ausente falha o build/boot (sem degradação silenciosa)?
- [ ] CORS do endpoint novo usa allowlist de origens?
- [ ] Security headers presentes nas respostas?
- [ ] CI do repo roda secret scan automatizado (gitleaks) além do scan manual do diff (P4)?
- [ ] Segredo insubstituível tem duas cópias independentes e restauração testada (R9)?
