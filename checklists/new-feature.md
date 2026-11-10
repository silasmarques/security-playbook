---
owasp: [A06]
last-review: 2026-11-10
---

# Checklist: Nova Feature (mini threat model)

> Rodar ANTES de codar — 10 minutos aqui evitam o retrabalho de "agora adiciona segurança". Este checklist é a materialização de Insecure Design (A06): segurança decidida no design, não remendada depois.

## 1. As 5 perguntas de ameaça

Para feature que toca dinheiro, dado sensível ou IA, preencher o modelo completo de [core/secure-design.md](../core/secure-design.md) P1 e guardar no projeto.

1. **Dados:** que dados a feature toca? Qual é o pior vazamento possível com eles?
2. **Acesso:** quem PODE e quem NÃO PODE executar cada operação? Como isso é imposto no servidor?
3. **Entrada:** que input externo entra (forms, params, arquivos, webhooks, conteúdo de LLM) e por onde?
4. **Saída:** que chamadas saem (APIs de terceiros, fetch dinâmico, modelo de IA)? O que custa cada uma?
5. **Falha:** o que acontece se cada dependência falhar, demorar ou responder maliciosamente?

## 2. Roteamento — da resposta para o módulo

| Se a resposta envolve... | Consultar |
|---|---|
| Dados de usuário em tabela nova/alterada | [stack/supabase-rls.md](../stack/supabase-rls.md) |
| Operação que nem todos podem fazer | [core/authorization.md](../core/authorization.md) |
| Login, sessão, token, reset | [core/authentication.md](../core/authentication.md) |
| Qualquer input externo | [core/input-validation.md](../core/input-validation.md) |
| Upload de arquivo | [core/input-validation.md](../core/input-validation.md) R4 + [stack/supabase-rls.md](../stack/supabase-rls.md) P2 |
| Fetch/integração com URL dinâmica | [core/authorization.md](../core/authorization.md) P2 (SSRF) + [core/error-handling-resilience.md](../core/error-handling-resilience.md) |
| Chamada a modelo de IA, RAG, BYOK | [stack/ai-llm-security.md](../stack/ai-llm-security.md) |
| Operação cara (IA, e-mail, export) | [core/api-security.md](../core/api-security.md) R2/P2 (rate limit + cap) |
| Saldo, cota, cupom, "checar e alterar" | [core/api-security.md](../core/api-security.md) R10/P4 (operação atômica) |
| Papel, plano ou outro campo de poder | [stack/supabase-rls.md](../stack/supabase-rls.md) R9/P5 (privilégio por coluna) |
| Organizações / times | [core/authorization.md](../core/authorization.md) R8 |
| Dado pessoal novo | [core/secure-design.md](../core/secure-design.md) R3/R8 (classe, retenção, exclusão) |
| Dado sensível armazenado | [core/crypto-data-protection.md](../core/crypto-data-protection.md) |
| Secret/credencial nova | [core/secrets-config.md](../core/secrets-config.md) |
| Dependência nova | [core/dependencies-supply-chain.md](../core/dependencies-supply-chain.md) P3 |
| Renderizar conteúdo de usuário/LLM | [core/frontend-security.md](../core/frontend-security.md) |
| Escrever os testes de segurança da feature | [core/security-testing.md](../core/security-testing.md) |

## 3. Critérios de pronto (a feature só está completa com — ver [core/security-testing.md](../core/security-testing.md))

- [ ] Teste de isolamento: usuário A não acessa o recurso de B (com controle positivo: o dono acessa)
- [ ] Teste de validação: input malformado/excessivo é rejeitado com 400
- [ ] Rate limit/cap verificado na prática (estourar o limite em teste → 429)
- [ ] Eventos de segurança da feature aparecem no log estruturado
- [ ] Operação de saldo/cota testada com requisições em paralelo
- [ ] [pre-commit.md](pre-commit.md) verde no commit final
