---
owasp: [A01, A02, A03, A04, A05, A06, A07, A08, A09, A10]
last-review: 2026-06-11
---

# Checklist: Auditoria de Sistema Existente (pente fino)

> Para quando o sistema JÁ existe e você quer saber se está nos conformes. O roteiro percorre o playbook inteiro contra o código real e termina com um relatório priorizado. Com uma IA, uma auditoria completa leva de 1 a 3 sessões; o prompt pronto está no final.

## Etapa 1 — Inventário (mapear a superfície)

Antes de auditar, liste o que existe. Sem inventário, a auditoria audita só o que lembra.

- [ ] **Endpoints/funções:** todos os handlers HTTP (Edge Functions, rotas de API) — nome e o que fazem
- [ ] **Tabelas e buckets:** todas as tabelas do schema exposto + buckets de Storage
- [ ] **Pontos de entrada de dados:** forms, uploads, webhooks, integrações que RECEBEM dados
- [ ] **Chamadas de saída:** APIs de terceiros, fetches dinâmicos, chamadas a modelos de IA
- [ ] **Secrets:** todas as variáveis de ambiente/chaves e ONDE vivem
- [ ] **Dependências:** `package.json` + lockfile presentes

## Etapa 2 — Varredura por módulo

Rodar o **Checklist** de cada módulo contra o inventário. Ordem sugerida (do mais crítico ao menos):

| # | Módulo | Aplicar sobre |
|---|---|---|
| 1 | [supabase-rls](../stack/supabase-rls.md) | cada tabela e bucket do inventário |
| 2 | [authorization](../core/authorization.md) | cada endpoint (helper central? anti-IDOR? SSRF nos fetches?) |
| 3 | [authentication](../core/authentication.md) | fluxos de login/sessão/reset |
| 4 | [api-security](../core/api-security.md) | cada endpoint (prólogo completo? rate limit nos caros?) |
| 5 | [input-validation](../core/input-validation.md) | cada ponto de entrada de dados |
| 6 | [secrets-config](../core/secrets-config.md) | cada secret + headers + CORS |
| 7 | [ai-llm-security](../stack/ai-llm-security.md) | cada feature de IA (se houver) |
| 8 | [crypto-data-protection](../core/crypto-data-protection.md) | dados sensíveis armazenados |
| 9 | [error-handling-resilience](../core/error-handling-resilience.md) | catches, timeouts, retries |
| 10 | [logging-monitoring](../core/logging-monitoring.md) | o que é logado e o que deveria ser |
| 11 | [dependencies-supply-chain](../core/dependencies-supply-chain.md) | `npm audit` + CI |
| 12 | [frontend-security](../core/frontend-security.md) + [react-typescript](../stack/react-typescript.md) | innerHTML, CSP, tsconfig, redirects |

## Etapa 3 — Cobertura OWASP

- [ ] Conferir no [owasp-mapping.md](../owasp-mapping.md) se alguma categoria ficou sem verificação na Etapa 2

## Etapa 4 — Relatório priorizado

Cada achado vira uma linha com:

```text
[CRÍTICO|ALTO|MÉDIO|BAIXO] <onde> — <o quê> — <regra violada> — <correção sugerida>
```

Critério de severidade: **CRÍTICO** = exploração direta expõe dados/dinheiro (RLS ausente, IDOR, secret vazado); **ALTO** = exploração viável com esforço (sem rate limit em IA, CORS aberto); **MÉDIO** = defesa em profundidade ausente (sem timeout, log fraco); **BAIXO** = higiene (TS não-estrito, header faltando).

- [ ] Achados CRÍTICOS corrigidos antes de qualquer outra coisa
- [ ] Demais achados viram issues/backlog com a severidade na etiqueta

## Prompt pronto (para usar com sua IA)

```text
Faça uma auditoria de segurança deste projeto usando o security-playbook
(<caminho-do-clone>/SECURITY.md).

Siga o roteiro de checklists/audit.md:
1. Monte o inventário (Etapa 1) lendo o código real do projeto.
2. Percorra os checklists dos módulos na ordem da Etapa 2, conferindo cada
   item contra o código — cite arquivo e linha do achado.
3. Confira a cobertura OWASP (Etapa 3).
4. Entregue o relatório priorizado no formato da Etapa 4.

Não corrija nada ainda — primeiro o relatório completo, depois decidimos juntos.
```

> Dica: em projetos grandes, rode uma etapa por sessão (inventário → varredura
> 1-6 → varredura 7-12 → relatório) para manter a qualidade da análise.
