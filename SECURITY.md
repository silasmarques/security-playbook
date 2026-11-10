# Security Playbook — Norte de Segurança

> Documento normativo de segurança para os projetos que adotam este playbook: regras inegociáveis + roteamento para os módulos. Vale para qualquer stack; onde a regra cita Supabase/Postgres, é a forma concreta dela na stack com adaptador pronto. Rastreabilidade: [owasp-mapping.md](owasp-mapping.md) (OWASP Top 10:2025).
> **Para a IA:** leia este arquivo ao tocar superfície de segurança; siga o Bloco 2 para saber qual módulo abrir. Instruções de uso no Bloco 3.

---

## Bloco 1 — As Inegociáveis

Violação de qualquer item abaixo é bug de segurança, independente de contexto. Exceção exige decisão explícita do dono do projeto, registrada no ponto do código e no `SECURITY-STATUS.md` do projeto.

1. **Nunca commitar secrets.** Vazou → rotacionar imediatamente; remover do histórico não basta. Segredo que não se rotaciona (chave de assinatura, chave de dados) tem duas cópias independentes e restauração testada. [A02]
2. **Todo dado de usuário é isolado na camada de dados.** Toda tabela exposta tem RLS (inclusive a "interna"); o filtro é por `auth.uid()`; credencial que ignora RLS (`service_role`) filtra dono explicitamente no código. [A01]
3. **Todo endpoint autentica E autoriza no servidor.** Deny by default. Identidade vem de token validado pelo servidor, nunca do request. Frontend esconde UI; não protege dados. [A01][A07]
4. **Autorização em nível de objeto:** o recurso pedido pertence ao chamador? Toda busca por ID carrega filtro de dono — e de organização, se houver (anti-IDOR). [A01]
5. **Todo input externo é validado com schema na fronteira** — inclusive output de LLM. Campo desconhecido é rejeitado. [A05]
6. **Queries sempre parametrizadas.** Nunca SQL/comando por concatenação. [A05]
7. **Erros nunca vazam internals.** Cliente recebe genérico + requestId; falha em checagem de segurança = NEGAR (fail closed). [A10]
8. **Toda chamada externa tem timeout.** Retry só transitório, com backoff e idempotência. [A10]
9. **Criptografia só com primitivas padrão** (AES-256-GCM com chave aleatória de 256 bits, senha via provedor); CSPRNG para aleatoriedade; comparações de segredo em tempo constante. [A04]
10. **URL de saída dinâmica passa por validação SSRF** (IPs privados/metadata em todas as formas; redirects revalidados; resposta com teto). [A01]
11. **Operação cara (IA, e-mail, export) tem rate limit e cap de custo por usuário** — antes de processar, com o limite definido no servidor. [A01]
12. **Lockfile commitado + audit no CI.** Dependência nova passa pelas 5 perguntas; action de terceiro fixada por SHA. [A03][A08]
13. **Logs: eventos de segurança SIM; secrets/tokens/PII NÃO.** Operação crítica vai para trilha de auditoria append-only. [A09]
14. **CORS por allowlist + security headers em toda resposta, inclusive as de erro.** Nunca `*` em rota autenticada, nunca `null`. [A02]
15. **Tipos estritos; `unknown` + schema nas fronteiras.** Conteúdo externo em prompt de LLM sempre delimitado como dado. [A06][A05]
16. **Mudança de config/deploy é verificada no ambiente real, e verificação precisa poder falhar.** Saber build-time vs runtime; config crítica ausente falha o build/boot (nunca degrada em silêncio); validar o artefato publicado, não um proxy. [A02]
17. **Campo de poder não é escrito pelo usuário** (papel, plano, saldo, bloqueio): privilégio por coluna no banco. "Checar e depois alterar" é um comando atômico. [A01]

## Bloco 2 — Roteamento: "vou fazer X → leio Y"

| Tarefa | Módulo(s) | Checklist |
|---|---|---|
| Endpoint / Edge Function nova | [stack/edge-functions-deno.md](stack/edge-functions-deno.md) + [core/api-security.md](core/api-security.md) | [pre-commit](checklists/pre-commit.md) |
| Tabela / migration nova | [stack/supabase-rls.md](stack/supabase-rls.md) | [pre-commit](checklists/pre-commit.md) |
| Formulário / input novo | [core/input-validation.md](core/input-validation.md) | [pre-commit](checklists/pre-commit.md) |
| Upload de arquivo | [core/input-validation.md](core/input-validation.md) P3 + [stack/supabase-rls.md](stack/supabase-rls.md) P2 | [pre-commit](checklists/pre-commit.md) |
| Login / sessão / reset / OAuth | [core/authentication.md](core/authentication.md) | [pre-commit](checklists/pre-commit.md) |
| Permissões / papéis / organizações | [core/authorization.md](core/authorization.md) + [stack/supabase-rls.md](stack/supabase-rls.md) P5 | [pre-commit](checklists/pre-commit.md) |
| Integração com API externa / fetch dinâmico / webhook | [core/authorization.md](core/authorization.md) P2 + [core/error-handling-resilience.md](core/error-handling-resilience.md) | [pre-commit](checklists/pre-commit.md) |
| Saldo, créditos, cota, pagamento | [core/api-security.md](core/api-security.md) P2/P4 | [new-feature](checklists/new-feature.md) |
| Feature com IA / LLM / RAG / BYOK | [stack/ai-llm-security.md](stack/ai-llm-security.md) + [core/api-security.md](core/api-security.md) P2 | [new-feature](checklists/new-feature.md) |
| Configurar agente de codificação / instalar MCP server | [stack/agentic-security.md](stack/agentic-security.md) | [pre-commit](checklists/pre-commit.md) |
| Armazenar dado sensível / criptografar | [core/crypto-data-protection.md](core/crypto-data-protection.md) | [pre-commit](checklists/pre-commit.md) |
| Secret / variável de ambiente nova | [core/secrets-config.md](core/secrets-config.md) | [pre-commit](checklists/pre-commit.md) |
| Dependência nova / upgrade / CI | [core/dependencies-supply-chain.md](core/dependencies-supply-chain.md) | [pre-commit](checklists/pre-commit.md) |
| Tratamento de erro / retry / timeout | [core/error-handling-resilience.md](core/error-handling-resilience.md) | [pre-commit](checklists/pre-commit.md) |
| Logging / auditoria / alertas | [core/logging-monitoring.md](core/logging-monitoring.md) | [pre-commit](checklists/pre-commit.md) |
| Componente React / renderizar conteúdo externo | [core/frontend-security.md](core/frontend-security.md) + [stack/react-typescript.md](stack/react-typescript.md) | [pre-commit](checklists/pre-commit.md) |
| Escrever testes de segurança / critérios de aceite | [core/security-testing.md](core/security-testing.md) | [new-feature](checklists/new-feature.md) |
| Desenhar arquitetura / dados pessoais / backup / incidente | [core/secure-design.md](core/secure-design.md) | [new-feature](checklists/new-feature.md) |
| Planejar feature nova | [prompts/pre-implementation.md](prompts/pre-implementation.md) | [new-feature](checklists/new-feature.md) (antes de codar) |
| Criar projeto novo | [kit/README.md](kit/README.md) (instalar o kit) | [new-project](checklists/new-project.md) |
| Revisar diff / PR (relatório completo) | [prompts/security-review.md](prompts/security-review.md) | [pre-commit](checklists/pre-commit.md) |
| Explorar falhas em sistema existente | [explore/README.md](explore/README.md) + [explore/hunts/](explore/hunts/acesso-cruzado.md) | [audit](checklists/audit.md) |
| Antes de commitar | — | [pre-commit](checklists/pre-commit.md) |

## Bloco 3 — Instruções de uso para a IA

1. **Quando consultar:** ao implementar ou revisar código que toque superfície de segurança (auth, autorização, input externo, queries, secrets, criptografia, chamadas externas, erro, logging, dependências, IA/LLM), ler este arquivo e o(s) módulo(s) do roteamento ANTES de escrever o código. Quando o usuário pedir explicitamente, a consulta é integral.
2. **Copie do kit, não reescreva de memória.** Os "Padrões prontos" vêm de [kit/](kit/README.md), onde cada um tem teste. Uma versão reescrita "parecida" perde exatamente os casos que os testes cobrem (as formas de IP no SSRF, o campo a mais no schema, o `REVOKE` da função). Se o projeto já tem o kit instalado, importe.
3. **Como reportar — dois modos.** (a) **Implementando:** reporte enxuto de 1–3 linhas ao concluir, dizendo quais regras se aplicaram e como (ex.: "api-security R1/R2: prólogo completo + rate limit; supabase-rls P1: migration com RLS e índice"). (b) **Revisando/explorando:** relatório por achado no formato de [explore/PROTOCOLO.md](explore/PROTOCOLO.md).
4. **Nenhuma afirmação sem evidência.** Achado é **confirmado** (com prova: execução, estado do artefato ou rastro completo no código) ou **suspeito** (dizendo o que falta verificar). Nunca "provavelmente". "Está seguro" e "não encontrei nada" também são afirmações: só valem acompanhadas do que foi analisado e do que **não** foi. Teste que você diz ter rodado, você rodou.
5. **Conflito com código existente:** se o código atual viola o playbook, SINALIZAR a divergência ao usuário — não copiar o padrão inseguro, nem "consertar" silenciosamente fora do escopo da tarefa.
6. **Norma, não sugestão:** o playbook prevalece sobre conveniência. Exceção só com decisão explícita do usuário, registrada no ponto do código (`playbook-ignore: <REGRA> <motivo>`) e no `SECURITY-STATUS.md`.
7. **Não inventar:** se uma situação não está coberta — outra stack, outro tipo de sistema —, dizer isso e propor com base nos princípios do Bloco 1 e de [core/](core/secure-design.md), marcando o que é hipótese a validar.

---

*Estrutura: 12 módulos em [core/](core/) (princípios universais) + 5 em [stack/](stack/) (TS/React/Supabase/Deno/IA/agentes) · [kit/](kit/README.md) (o código dos padrões, testado) · [explore/](explore/README.md) (varredura + roteiros de caça) · [checklists/](checklists/) · [prompts/](prompts/). Manutenção: ver [README.md](README.md).*
