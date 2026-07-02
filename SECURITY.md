# Security Playbook — Norte de Segurança

> Documento normativo de segurança para os projetos que adotam este playbook. Regras inegociáveis + roteamento para os módulos. Rastreabilidade: [owasp-mapping.md](owasp-mapping.md) (OWASP Top 10:2025).
> **Para a IA:** leia este arquivo ao tocar superfície de segurança; siga o Bloco 2 para saber qual módulo abrir. Instruções de uso no Bloco 3.

---

## Bloco 1 — As Inegociáveis

Violação de qualquer item abaixo é bug de segurança, independente de contexto. Exceção exige decisão explícita do dono do projeto, registrada em comentário no código.

1. **Nunca commitar secrets.** Vazou → rotacionar imediatamente; remover do histórico não basta. [A02]
2. **Toda tabela tem RLS habilitado.** Dados de usuário sempre filtrados server-side por `auth.uid()`; `service_role` bypassa RLS, então código server-side filtra dono explicitamente. [A01]
3. **Todo endpoint autentica E autoriza no servidor.** Deny by default. Frontend esconde UI; não protege dados. [A01][A07]
4. **Autorização em nível de objeto:** o recurso pedido pertence ao chamador? Toda busca por ID carrega filtro de dono (anti-IDOR). [A01]
5. **Todo input externo é validado com schema na fronteira** — inclusive output de LLM. [A05]
6. **Queries sempre parametrizadas.** Nunca SQL/comando por concatenação. [A05]
7. **Erros nunca vazam internals.** Cliente recebe genérico + requestId; falha em checagem de segurança = NEGAR (fail closed). [A10]
8. **Toda chamada externa tem timeout.** Retry só transitório, com backoff e idempotência. [A10]
9. **Criptografia só com primitivas padrão** (AES-256-GCM, argon2id via provedor); CSPRNG para aleatoriedade; comparações de segredo timing-safe. [A04]
10. **URL de saída dinâmica passa por validação SSRF** (IPs privados/metadata em todas as formas; redirects revalidados). [A01]
11. **Operação cara (IA, e-mail, export) tem rate limit e cap de custo por usuário** — antes de processar. [A01]
12. **Lockfile commitado + audit no CI.** Dependência nova passa pelas 5 perguntas. [A03][A08]
13. **Logs: eventos de segurança SIM; secrets/tokens/PII NÃO.** Operação crítica vai para `audit_log`. [A09]
14. **CORS por allowlist + security headers em toda resposta.** Nunca `*` com credenciais. [A02]
15. **TypeScript estrito; `unknown` + schema nas fronteiras.** Conteúdo externo em prompt de LLM sempre delimitado como dado. [A06][A05]

## Bloco 2 — Roteamento: "vou fazer X → leio Y"

| Tarefa | Módulo(s) | Checklist |
|---|---|---|
| Endpoint / Edge Function nova | [stack/edge-functions-deno.md](stack/edge-functions-deno.md) + [core/api-security.md](core/api-security.md) | [pre-commit](checklists/pre-commit.md) |
| Tabela / migration nova | [stack/supabase-rls.md](stack/supabase-rls.md) | [pre-commit](checklists/pre-commit.md) |
| Formulário / input novo | [core/input-validation.md](core/input-validation.md) | [pre-commit](checklists/pre-commit.md) |
| Upload de arquivo | [core/input-validation.md](core/input-validation.md) + [stack/supabase-rls.md](stack/supabase-rls.md) P2 | [pre-commit](checklists/pre-commit.md) |
| Login / sessão / reset / JWT | [core/authentication.md](core/authentication.md) | [pre-commit](checklists/pre-commit.md) |
| Permissões / acesso a recurso | [core/authorization.md](core/authorization.md) | [pre-commit](checklists/pre-commit.md) |
| Integração com API externa / fetch dinâmico | [core/authorization.md](core/authorization.md) P2 + [core/error-handling-resilience.md](core/error-handling-resilience.md) | [pre-commit](checklists/pre-commit.md) |
| Feature com IA / LLM / RAG / BYOK | [stack/ai-llm-security.md](stack/ai-llm-security.md) + [core/api-security.md](core/api-security.md) P2 | [new-feature](checklists/new-feature.md) |
| Armazenar dado sensível / criptografar | [core/crypto-data-protection.md](core/crypto-data-protection.md) | [pre-commit](checklists/pre-commit.md) |
| Secret / variável de ambiente nova | [core/secrets-config.md](core/secrets-config.md) | [pre-commit](checklists/pre-commit.md) |
| Dependência nova / upgrade | [core/dependencies-supply-chain.md](core/dependencies-supply-chain.md) | [pre-commit](checklists/pre-commit.md) |
| Tratamento de erro / retry / timeout | [core/error-handling-resilience.md](core/error-handling-resilience.md) | [pre-commit](checklists/pre-commit.md) |
| Logging / auditoria / alertas | [core/logging-monitoring.md](core/logging-monitoring.md) | [pre-commit](checklists/pre-commit.md) |
| Componente React / renderizar conteúdo externo | [core/frontend-security.md](core/frontend-security.md) + [stack/react-typescript.md](stack/react-typescript.md) | [pre-commit](checklists/pre-commit.md) |
| Escrever testes de segurança / critérios de aceite | [core/security-testing.md](core/security-testing.md) | [new-feature](checklists/new-feature.md) |
| Revisar diff / PR (relatório completo) | [prompts/security-review.md](prompts/security-review.md) | [pre-commit](checklists/pre-commit.md) |
| Planejar feature nova | [prompts/pre-implementation.md](prompts/pre-implementation.md) | [new-feature](checklists/new-feature.md) (antes de codar) |
| Criar projeto novo | — | [new-project](checklists/new-project.md) |
| Antes de commitar | — | [pre-commit](checklists/pre-commit.md) |
| Auditar sistema existente (pente fino) | todos, na ordem do roteiro | [audit](checklists/audit.md) |

## Bloco 3 — Instruções de uso para a IA

1. **Quando consultar:** ao implementar ou revisar código que toque superfície de segurança (auth, autorização, input externo, queries, secrets, criptografia, chamadas externas, erro, logging, dependências, IA/LLM), ler este arquivo e o(s) módulo(s) do roteamento ANTES de escrever o código. Quando o usuário pedir explicitamente, a consulta é integral.
2. **Como reportar — dois modos.** (a) **Implementando:** reporte enxuto de 1–3 linhas ao concluir a tarefa, dizendo quais regras se aplicaram e como (ex.: "api-security R1/R2 ok: prólogo completo + rate limit; supabase-rls P1: migration com RLS e índice"). (b) **Revisando/auditando** (usuário pediu revisão de diff, PR ou sistema): relatório completo por achado no formato de [prompts/security-review.md](prompts/security-review.md) — Risco / Por que importa / Onde / Como corrigir / Teste recomendado / BDD quando fizer sentido, com severidade e OWASP/CWE.
3. **Conflito com código existente:** se o código atual viola o playbook, SINALIZAR a divergência ao usuário — não copiar o padrão inseguro, nem "consertar" silenciosamente fora do escopo da tarefa.
4. **Norma, não sugestão:** o playbook prevalece sobre conveniência. Exceção só com decisão explícita do usuário, registrada em comentário no ponto do código.
5. **Não inventar:** se uma situação não está coberta, dizer isso e propor com base nos princípios do Bloco 1 — marcando o que é hipótese a validar.

---

*Estrutura: 11 módulos em [core/](core/) (princípios universais) + 4 em [stack/](stack/) (TS/React/Supabase/Deno/IA) + 4 [checklists/](checklists/) + 2 [prompts/](prompts/). Manutenção: ver [README.md](README.md).*
