---
owasp: [A03, A08]
last-review: 2026-11-10
sources:
  - https://owasp.org/Top10/2025/
  - https://cheatsheetseries.owasp.org/cheatsheets/Vulnerable_Dependency_Management_Cheat_Sheet.html
  - https://docs.npmjs.com/cli/commands/npm-audit
  - https://docs.github.com/en/code-security/dependabot/working-with-dependabot/dependabot-options-reference
  - https://docs.renovatebot.com/configuration-options/
  - https://docs.github.com/en/actions/reference/security/secure-use
---

# Dependências e Supply Chain

> Software Supply Chain Failures estreou em 3º lugar na OWASP 2025 — seu código pode estar perfeito e o sistema comprometido por um `npm install`. Cada dependência é código de terceiros rodando com as suas permissões.

## Regras

- **R1 — MUST** lockfile commitado sempre (`package-lock.json` / `deno.lock`); CI instala com `npm ci` (respeita o lockfile), nunca `npm install`.
- **R2 — MUST** auditoria de vulnerabilidades no CI (`npm audit` ou OSV-Scanner); build falha em high/critical com correção disponível.
- **R3 — MUST** avaliar antes de adicionar dependência (as 5 perguntas do P3). Menos dependência = menos superfície; 30 linhas próprias muitas vezes valem mais que um pacote com 40 dependências transitivas.
- **R4 — NEVER** rodar instaladores não auditados (`curl ... | bash`, `npx pacote-desconhecido`). Conferir o nome EXATO do pacote — typosquatting (`react-dom` vs `reactdom`) é vetor ativo.
- **R5 — MUST** atualizações automatizadas (Dependabot/Renovate) com review humano antes do merge — atualizar rápido fecha vulnerabilidades, mas merge cego instala release comprometida.
- **R6 — MUST** scripts de CDN com SRI (`integrity="sha384-..."`); preferível: tudo via bundle, sem CDN de terceiros em runtime.
- **R7 — MUST** CI com permissões mínimas: `permissions: contents: read` como default do workflow; secrets só nos jobs que deles precisam; nunca em jobs que rodam código de PR de fork.
- **R8 — NEVER** instalar pacote sugerido por IA sem verificar que existe, é o pacote certo e é mantido (slopsquatting: atacantes registram nomes que LLMs alucinam).
- **R10 — MUST** GitHub Actions de terceiros fixadas pelo **SHA completo do commit** (com a versão em comentário), não por tag. Tag é móvel: quem compromete o repositório da action reaponta `v4` e o seu CI executa o código dele com os seus secrets. Vale para toda action fora da sua organização.
- **R9 — MUST** cooldown de release nos updates automatizados: aguardar ≥ 3 dias (major: 7) antes de adotar versão recém-publicada. Os grandes comprometimentos de pacotes npm de 2025 foram detectados e removidos em horas — quem instalou no dia zero foi atingido; quem esperou, não. Exceção: patch para vulnerabilidade sendo explorada entra imediatamente, com review.

## Padrões prontos

### P1 — Workflow CI mínimo de segurança (GitHub Actions)

```yaml
name: ci
on: [push, pull_request]

permissions:
  contents: read            # default mínimo para TODO o workflow

jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262 # v4.4.0
      - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4.4.0
        with: { node-version: 22, cache: npm }
      - run: npm ci                              # respeita o lockfile
      - run: npm audit --audit-level=high        # falha em high/critical
      - run: npx tsc --noEmit                    # zero erros de tipo
      - run: npm test
```

### P2 — Dependabot básico

```yaml
# .github/dependabot.yml
version: 2
updates:
  - package-ecosystem: npm
    directory: "/"
    schedule: { interval: weekly }
    open-pull-requests-limit: 5
    groups:
      minor-and-patch:
        update-types: ["minor", "patch"]   # agrupa o ruído; majors vêm sozinhos
    cooldown:                              # R9: release recém-saída espera maturar
      default-days: 3
      semver-major-days: 7
```

> Renovate: o equivalente é `"minimumReleaseAge": "3 days"`. O `cooldown` do Dependabot vale só para atualizações de versão — atualização de segurança entra sem espera. Sintaxe reconferida na doc oficial em 2026-11-10. Para manter os SHAs das actions atualizados, acrescentar `package-ecosystem: github-actions` ao mesmo arquivo.

### P3 — As 5 perguntas antes de adicionar dependência

```text
1. É mantida?       Último release < 12 meses; issues respondidas; não arquivada.
2. É a certa?       Nome exato conferido no registry (typosquatting); é a lib
                    que a comunidade usa para isso, não um clone.
3. Qual o custo?    Quantas dependências transitivas traz? (npm ls --all | wc)
                    Tem script de install (postinstall)? Por quê?
4. Dá para evitar?  A funcionalidade cabe em ~30 linhas próprias e testadas?
                    A plataforma já faz (Web Crypto, fetch, Intl)?
5. Quem assina?     Autor/org conhecidos? Repo público com código que bate com
                    o pacote publicado?
Reprovou em 2+ → não entra.
```

## Anti-padrões

```jsonc
// ❌ NUNCA: versão flutuante — instala "o que vier" amanhã [viola R1]
{ "dependencies": { "some-lib": "*", "other-lib": "latest" } }
```

```bash
# ❌ NUNCA: deletar lockfile para "resolver conflito" [viola R1]
rm package-lock.json && npm install
# Reresolve TODAS as versões — qualquer release comprometida do intervalo entra.

# ❌ NUNCA: pipe de instalador sem auditar [viola R4]
curl -fsSL https://exemplo.com/install.sh | bash

# ❌ NUNCA: aceitar sugestão de pacote sem conferir [viola R8]
npm install supabase-edge-helpers   # existe? é oficial? quem publicou?
```

## Checklist

- [ ] Lockfile presente no diff quando dependências mudaram?
- [ ] `npm audit` sem high/critical novo?
- [ ] Dependência nova passou pelas 5 perguntas (P3)?
- [ ] Nenhum script de CDN sem SRI?
- [ ] Workflows novos com `permissions` mínimas e secrets só onde precisa?
- [ ] Dependabot/Renovate ativo no repo?
- [ ] Cooldown de release configurado nos updates automatizados (R9)?
- [ ] Actions de terceiros fixadas por SHA de commit (R10)?
