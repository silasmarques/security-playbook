---
owasp: [A02, A05, A09]
last-review: 2026-06-11
---

# Checklist: Antes de Commitar

> Rodar sobre o diff staged, antes de todo commit que vai para review/push. Itens objetivos — sim ou não.

## Automatizável (rodar de fato)

- [ ] **Secrets:** scan do diff vazio →
  `git diff --cached | Select-String -Pattern 'api[_-]?key|secret|password|token|BEGIN.*PRIVATE KEY' -CaseSensitive:$false`
  (detalhes: [core/secrets-config.md](../core/secrets-config.md) P3)
- [ ] **Tipos:** `npx tsc --noEmit` → zero erros ([stack/react-typescript.md](../stack/react-typescript.md) R3)
- [ ] **Dependências:** se `package.json` mudou — lockfile no diff e `npm audit --audit-level=high` limpo ([core/dependencies-supply-chain.md](../core/dependencies-supply-chain.md))
- [ ] **Testes:** `npm test` passando, incluindo os de lógica de segurança

## Inspeção do diff

- [ ] Nenhum `console.log` de dado sensível nem código de debug esquecido ([core/logging-monitoring.md](../core/logging-monitoring.md) R2)
- [ ] Endpoint novo segue o prólogo completo: auth → acesso → rate limit → validação ([core/api-security.md](../core/api-security.md) P1)
- [ ] Tabela/migration nova: RLS + 4 policies + índice ([stack/supabase-rls.md](../stack/supabase-rls.md) P1)
- [ ] Input novo validado com schema na fronteira ([core/input-validation.md](../core/input-validation.md))
- [ ] Nenhum catch vazio; erros respondem genérico e logam detalhado ([core/error-handling-resilience.md](../core/error-handling-resilience.md))
- [ ] Nenhum `dangerouslySetInnerHTML`/`innerHTML` fora do wrapper ([core/frontend-security.md](../core/frontend-security.md) P1)
- [ ] Conteúdo externo novo que vai a prompt passa por `wrapUntrustedContent` ([stack/ai-llm-security.md](../stack/ai-llm-security.md) P1)

> Falhou um item → resolver antes do commit, não "depois eu arrumo".
