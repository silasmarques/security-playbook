---
owasp: [A02, A03, A06]
last-review: 2026-11-10
---

# Checklist: Projeto Novo (setup seguro)

> Em ordem de execução. Segurança configurada no dia 1 é grátis; retrofit custa semanas. Cada item aponta o padrão pronto para copiar.

## Antes do primeiro commit

- [ ] `.gitignore` com `.env*`, `*.pem`, `*.key` ([core/secrets-config.md](../core/secrets-config.md) P3)
- [ ] `.env.example` com os NOMES das variáveis, sem valores

## Desenho (antes do código)

- [ ] Modelo de isolamento decidido — por usuário, por organização ou ambos ([core/secure-design.md](../core/secure-design.md) R4)
- [ ] Classes de dados definidas ([core/secure-design.md](../core/secure-design.md) P2)
- [ ] `SECURITY-STATUS.md` criado na raiz a partir do [modelo](../templates/SECURITY-STATUS.md), com o inventário de segredos

## Configuração base

- [ ] `tsconfig` estrito desde o início ([stack/react-typescript.md](../stack/react-typescript.md) P1)
- [ ] Validação de env no boot ([stack/react-typescript.md](../stack/react-typescript.md) P3)
- [ ] Lockfile commitado; Dependabot configurado ([core/dependencies-supply-chain.md](../core/dependencies-supply-chain.md) P2)
- [ ] CI mínimo: `npm ci` + `npm audit` + `tsc --noEmit` + testes, com `permissions` mínimas e actions fixadas por SHA ([core/dependencies-supply-chain.md](../core/dependencies-supply-chain.md) P1)
- [ ] Secret scan automatizado no CI (gitleaks) ([core/secrets-config.md](../core/secrets-config.md) P4)
- [ ] Security headers no host ([core/frontend-security.md](../core/frontend-security.md) P3)

## Supabase (se aplicável)

- [ ] Template de migration com RLS + policies + índice como padrão ([stack/supabase-rls.md](../stack/supabase-rls.md) P1)
- [ ] Buckets privados por padrão, policy por pasta ([stack/supabase-rls.md](../stack/supabase-rls.md) P2)
- [ ] Kit instalado ANTES da primeira função: `deno run --allow-read --allow-write <playbook>/kit/install.ts . --sql` — cria `_shared/` com os helpers testados e o `_template` de função ([kit](../kit/README.md); [stack/edge-functions-deno.md](../stack/edge-functions-deno.md) R4)
- [ ] `ALLOWED_ORIGINS` definida nos secrets de cada ambiente (sem ela a função não sobe)
- [ ] Secrets registrados por ambiente no inventário ([core/secrets-config.md](../core/secrets-config.md) P1)
- [ ] Rate limiting: migrations do kit aplicadas e cada ação cara cadastrada em `rate_limits` ([core/api-security.md](../core/api-security.md) P2)
- [ ] Tabela `audit_log` criada, append-only ([core/logging-monitoring.md](../core/logging-monitoring.md) P2)
- [ ] Tabela de perfil com privilégio por coluna para papel/plano ([stack/supabase-rls.md](../stack/supabase-rls.md) P5)

## Governança

- [ ] Branch `main` protegida no GitHub (require PR, CI verde)
- [ ] `CLAUDE.md` (ou arquivo de regras da sua IA) referenciando este playbook:
  `Segurança: seguir o SECURITY.md do security-playbook (regras inegociáveis + roteamento) — <caminho do seu clone>.`
- [ ] Se o projeto usa IA: caps de custo definidos ANTES da primeira feature de IA ([stack/ai-llm-security.md](../stack/ai-llm-security.md) R4)
- [ ] Segredo insubstituível (keystore, chave de dados): duas cópias independentes, restauração testada, registrado no inventário ([core/secrets-config.md](../core/secrets-config.md) R9)
- [ ] Backup do banco ligado e restauração testada uma vez; roteiro de incidente escrito ([core/secure-design.md](../core/secure-design.md) P3)
- [ ] Primeira varredura: `deno task explore .` com zero achados — o ponto de partida fica registrado no `SECURITY-STATUS.md`
