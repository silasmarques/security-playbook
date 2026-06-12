---
owasp: [A02, A03, A06]
last-review: 2026-06-11
---

# Checklist: Projeto Novo (setup seguro)

> Em ordem de execução. Segurança configurada no dia 1 é grátis; retrofit custa semanas. Cada item aponta o padrão pronto para copiar.

## Antes do primeiro commit

- [ ] `.gitignore` com `.env*`, `*.pem`, `*.key` ([core/secrets-config.md](../core/secrets-config.md) P3)
- [ ] `.env.example` com os NOMES das variáveis, sem valores

## Configuração base

- [ ] `tsconfig` estrito desde o início ([stack/react-typescript.md](../stack/react-typescript.md) P1)
- [ ] Validação de env no boot ([stack/react-typescript.md](../stack/react-typescript.md) P3)
- [ ] Lockfile commitado; Dependabot configurado ([core/dependencies-supply-chain.md](../core/dependencies-supply-chain.md) P2)
- [ ] CI mínimo: `npm ci` + `npm audit` + `tsc --noEmit` + testes ([core/dependencies-supply-chain.md](../core/dependencies-supply-chain.md) P1)
- [ ] Security headers no host ([core/frontend-security.md](../core/frontend-security.md) P3)

## Supabase (se aplicável)

- [ ] Template de migration com RLS + policies + índice como padrão ([stack/supabase-rls.md](../stack/supabase-rls.md) P1)
- [ ] Buckets privados por padrão, policy por pasta ([stack/supabase-rls.md](../stack/supabase-rls.md) P2)
- [ ] `_shared/` criado com os helpers ANTES da primeira função: `cors.ts`, `access-control.ts`, `error-boundary.ts`, `validation` ([stack/edge-functions-deno.md](../stack/edge-functions-deno.md) R4/P2)
- [ ] Secrets registrados por ambiente no inventário ([core/secrets-config.md](../core/secrets-config.md) P1)
- [ ] Rate limiting: tabela `usage_counters` + `check_and_increment` na primeira migration se haverá operação cara ([core/api-security.md](../core/api-security.md) P2)
- [ ] Tabela `audit_log` criada ([core/logging-monitoring.md](../core/logging-monitoring.md) P2)

## Governança

- [ ] Branch `main` protegida no GitHub (require PR, CI verde)
- [ ] `CLAUDE.md` (ou arquivo de regras da sua IA) referenciando este playbook:
  `Segurança: seguir o SECURITY.md do security-playbook (regras inegociáveis + roteamento) — <caminho do seu clone>.`
- [ ] Se o projeto usa IA: caps de custo definidos ANTES da primeira feature de IA ([stack/ai-llm-security.md](../stack/ai-llm-security.md) R4)
