# 🛡️ Security Playbook

**Um norte de segurança normativo para desenvolvimento de software — feito para ser consumido por humanos e por IAs de codificação (Claude Code, Cursor, Copilot e afins).**

> **Missão:** transformar conhecimento de segurança em prática de desenvolver, revisar e testar software com menos risco.
> **Princípio:** pensar como atacante, documentar como defensor, programar como engenheiro responsável.

Serve aos dois momentos da vida de um sistema:

- **Construindo:** a IA (ou você) consulta o playbook enquanto o código nasce — e ele já nasce seguro.
- **Mantendo:** rode o [pente fino](checklists/audit.md) num sistema que já existe e descubra, com relatório priorizado, o que está fora dos conformes.

Não é material de estudo nem coletânea de boas práticas genéricas: é **norma operacional**. Regras objetivas (MUST/NEVER), padrões de código prontos para copiar, anti-padrões com o ataque explicado, e checklists verificáveis — tudo rastreável à **OWASP Top 10:2025**.

---

## 📦 O que tem dentro

### A porta de entrada

**[SECURITY.md](SECURITY.md)** — 15 regras inegociáveis + tabela de roteamento ("vou fazer X → leio Y") + instruções de como uma IA deve consultar e reportar conformidade. É o único arquivo que precisa estar sempre à mão; o resto é consultado sob demanda.

### 11 módulos universais — [core/](core/)

Valem para qualquer stack web:

- **[authentication](core/authentication.md)** — Provar quem é o usuário, a cada request. Validação de JWT no servidor (assinatura, expiração, audiência), por que `getUser()` e não `getSession()` para decisões de segurança, revogação de sessão em eventos sensíveis, rate limit nos fluxos de credencial e mensagens de erro que não revelam quais contas existem.

- **[authorization](core/authorization.md)** — O que o usuário pode fazer depois de autenticado. Deny by default, checagem em nível de objeto (anti-IDOR: "esse recurso é mesmo seu?"), helper de acesso centralizado para nenhuma função "esquecer" a checagem, e validação SSRF de URLs de saída — cobrindo bypasses por encoding de IP (decimal, hex, octal, IPv6-mapped).

- **[input-validation](core/input-validation.md)** — A fronteira entre o mundo hostil e o seu código. Validação por schema (zod) de todo input externo, queries sempre parametrizadas contra injection, upload validado em 4 dimensões (extensão, content-type, tamanho, nome) e por que blocklist de "caracteres perigosos" nunca é a defesa.

- **[secrets-config](core/secrets-config.md)** — Onde cada tipo de chave deve morar (frontend público × secrets do servidor × CI), o que jamais pode ir para o bundle, separação por ambiente, o que fazer quando um secret vaza, security headers de referência e CORS por allowlist.

- **[crypto-data-protection](core/crypto-data-protection.md)** — Criptografia sem inventar moda. AES-256-GCM com IV único para dado que precisa voltar, hash para senha (nunca o contrário), CSPRNG para tokens, comparação timing-safe para HMAC/assinaturas e payloads assinados com expiração anti-replay.

- **[dependencies-supply-chain](core/dependencies-supply-chain.md)** — Defesa contra o ataque que chega via `npm install`. Lockfile + audit no CI, as 5 perguntas antes de adicionar qualquer pacote, typosquatting e slopsquatting (pacotes que IAs alucinam), SRI para CDN e permissões mínimas no pipeline.

- **[api-security](core/api-security.md)** — O esqueleto de um endpoint seguro. A ordem canônica do handler (CORS → método → auth → acesso → rate limit → validação), rate limiting por usuário com cap de custo nas operações caras, paginação com teto do servidor e erros padronizados com requestId.

- **[frontend-security](core/frontend-security.md)** — O que fazer quando seu código roda na máquina do atacante. XSS bloqueado por um único wrapper sanitizado (DOMPurify) em todo o projeto, URLs dinâmicas sem `javascript:`, CSP + frame-ancestors, e por que esconder botão é UX, não segurança.

- **[error-handling-resilience](core/error-handling-resilience.md)** — Como o sistema se comporta quando algo dá errado. Fail closed (erro na checagem de segurança = negar), nada de stack trace para o cliente, timeout em toda chamada externa, retry só com backoff e idempotência, e nenhum catch silencioso.

- **[logging-monitoring](core/logging-monitoring.md)** — Saber que o ataque aconteceu. Quais eventos de segurança logar e com qual estrutura, o que jamais pode ir para log (tokens, PII, chaves), anti log-injection, trilha de auditoria persistente e o alerta mínimo viável.

- **[security-testing](core/security-testing.md)** — Provar que os controles negam o acesso indevido, não só que o caminho feliz funciona. Teste negativo para todo controle, teste de acesso cruzado A×B (anti-IDOR), estouro de rate limit, vetores de input inválido na própria suíte e critérios de aceite em BDD defensivo (Gherkin). Pensar como atacante, verificado como teste.

### 5 módulos de stack — [stack/](stack/)

Aplicação concreta em TypeScript/React/Supabase/Deno (princípios transferíveis para stacks equivalentes):

- **[supabase-rls](stack/supabase-rls.md)** — A fronteira de dados quando a anon key é pública por design. RLS em toda tabela com policy por operação (incluindo o `WITH CHECK` que quase todo mundo esquece no UPDATE), índice nas colunas de policy, Storage com pasta por usuário, os perigos do `service_role` e do `SECURITY DEFINER`, e o teste de isolamento usuário A × usuário B.

- **[edge-functions-deno](stack/edge-functions-deno.md)** — Cada função é um endpoint público na internet. Template completo de função segura com o prólogo na ordem certa, helpers compartilhados em `_shared/` como única implementação, CORS por allowlist via env, webhooks verificados com HMAC timing-safe e secrets sem fallback.

- **[react-typescript](stack/react-typescript.md)** — TypeScript estrito como ferramenta de segurança. `unknown` + schema nas fronteiras em vez de `as`, env do Vite validada no boot, guard de rota único, redirect pós-login com allowlist (anti open redirect) e onde chaves digitadas pelo usuário não podem parar.

- **[ai-llm-security](stack/ai-llm-security.md)** ★ — O módulo diferencial. Prompt injection tratada com defesa em camadas (delimitação do conteúdo externo + instrução defensiva + score de risco no RAG + validação de output), chaves BYOK cifradas e write-only, rate limit e cap de custo antes de toda chamada de modelo, e tool-use com confirmação humana para ações destrutivas.

- **[agentic-security](stack/agentic-security.md)** ★ — O outro lado da moeda: segurança de quem **usa** agentes de codificação (Claude Code, Cursor) e MCP servers. Prompt injection via conteúdo do repositório, tool poisoning, a tríade letal (dados privados + conteúdo não confiável + canal de exfiltração), permissões mínimas no harness e review de diff de agente como código de terceiro.

★ Segurança de IA/LLM e de agentes tratada como cidadã de primeira classe — os módulos mais difíceis de encontrar prontos em outros guias.

### 4 checklists — [checklists/](checklists/)

| Checklist | Quando usar |
|---|---|
| [new-project](checklists/new-project.md) | Criando um projeto — segurança do dia 1 |
| [new-feature](checklists/new-feature.md) | Antes de codar uma feature — mini threat model em 5 perguntas |
| [pre-commit](checklists/pre-commit.md) | Antes de todo commit |
| [audit](checklists/audit.md) | Pente fino em sistema que já existe |

### 2 prompts prontos — [prompts/](prompts/)

Para colar numa sessão de IA já configurada com o playbook:

| Prompt | Quando usar |
|---|---|
| [pre-implementation](prompts/pre-implementation.md) | Antes de codar — riscos, critérios de aceite, BDD defensivo e cuidados por camada |
| [security-review](prompts/security-review.md) | Revisar um diff/PR/código — relatório completo por achado (Risco → Correção → Teste → BDD) |

### A prova de cobertura

**[owasp-mapping.md](owasp-mapping.md)** — matriz que mapeia cada categoria da OWASP Top 10:2025 aos módulos e regras que a cobrem, com rastreio às fraquezas do CWE Top 25:2025. Nada do Top 10 fica descoberto.

Cada módulo segue o mesmo formato: **Regras → Padrões prontos → Anti-padrões → Checklist**. Os padrões de código foram extraídos e generalizados de **sistemas reais em produção, auditados**.

---

## 🚀 Como usar — passo a passo

### Setup com IA de codificação (5 minutos)

**Passo 1 — Clone o playbook** em um caminho fixo da sua máquina:

```bash
git clone https://github.com/silasmarques/security-playbook.git
```

**Passo 2 — Cole este bloco no arquivo de regras da sua IA**, ajustando o caminho do clone:

- Claude Code → `~/.claude/CLAUDE.md` (global) ou `CLAUDE.md` do projeto
- Cursor → `.cursorrules`
- Copilot → `.github/copilot-instructions.md`

```markdown
## Security Playbook (obrigatório)

Norte de segurança: `<caminho-do-clone>/security-playbook/SECURITY.md`.

**Quando consultar (sem o usuário pedir):** ao implementar ou revisar código que toque
superfície de segurança — auth/sessão, autorização/acesso a dados, input externo
(forms, APIs, uploads, webhooks), queries, secrets/config, criptografia, chamadas
externas, tratamento de erro, logging, dependências novas, ou qualquer feature com IA/LLM.

**Como:** ler o SECURITY.md (inegociáveis + roteamento) e os módulos indicados para a
tarefa. Ao concluir, reportar brevemente quais regras se aplicaram. Conflito entre
playbook e código existente → sinalizar, não resolver silenciosamente.

**Sempre que o usuário pedir** ("consulta o playbook", "revisa a segurança disso"),
a consulta é integral: SECURITY.md + módulos relevantes + checklist aplicável.
```

**Passo 3 — Teste a adoção.** Numa sessão nova, peça *sem mencionar segurança*:

```text
Crie um endpoint de upload de documentos.
```

A IA deve consultar o roteamento, aplicar os módulos e reportar algo como *"api-security R1/R2 ok: prólogo completo + rate limit; input-validation P3: upload validado nas 4 dimensões"*. Se não consultou, confira o caminho do Passo 2.

**Passo 4 — Use no dia a dia.** Exemplos de pedidos e o que esperar:

| Você diz | A IA faz |
|---|---|
| "Cria a tabela de comentários" | Migration com RLS + 4 policies + índice ([supabase-rls](stack/supabase-rls.md) P1) |
| "Adiciona busca por URL externa" | Validação SSRF + timeout + redirect revalidado ([authorization](core/authorization.md) P2) |
| "Integra com a API do Gemini" | Rate limit + cap de custo ANTES da chamada ([ai-llm-security](stack/ai-llm-security.md)) |
| "Consulta o playbook e revisa esse diff" | Relatório completo por achado ([prompts/security-review.md](prompts/security-review.md)) + checklist [pre-commit](checklists/pre-commit.md) |
| "Analisa essa feature antes de eu codar" | Threat model + critérios de aceite + BDD ([prompts/pre-implementation.md](prompts/pre-implementation.md)) |

### Pente fino em sistema existente

Para auditar um sistema que já está no ar, use o roteiro completo de **[checklists/audit.md](checklists/audit.md)** — inventário → varredura módulo a módulo → cobertura OWASP → relatório priorizado por severidade. Lá tem um **prompt pronto** para colar na sua IA e iniciar a auditoria.

### Sem IA (uso humano)

1. **Projeto novo?** Siga [new-project.md](checklists/new-project.md) na ordem.
2. **Vai codar uma feature?** Responda as 5 perguntas de [new-feature.md](checklists/new-feature.md) (~10 min) e abra os módulos que o roteamento do [SECURITY.md](SECURITY.md) indicar.
3. **Vai commitar?** Passe o diff por [pre-commit.md](checklists/pre-commit.md).
4. **Dúvida pontual?** A tabela de roteamento do [SECURITY.md](SECURITY.md) diz qual módulo abrir.

---

## 🧭 Princípios de design

1. **Organizado por domínio, não por taxonomia** — os módulos seguem como se pensa ao codar ("estou mexendo em auth"), com a OWASP como camada de rastreabilidade.
2. **Índice enxuto + módulos sob demanda** — o `SECURITY.md` cabe no contexto de qualquer sessão de IA; os módulos só entram quando a tarefa pede.
3. **Todo padrão é copiável** — código real TS/SQL/Deno com os trade-offs comentados no lugar.
4. **Anti-padrões com o ataque junto** — cada "nunca faça" mostra o que o atacante ganharia.
5. **Norma nascida de produção** — as regras mais enfáticas vêm de lacunas encontradas em auditorias reais.

## 🔧 Manutenção e versões

- Cada módulo tem `last-review` e `sources` no frontmatter — afirmações não triviais citam fonte oficial (OWASP, docs Supabase/Deno/React).
- **Cadência de revisão:** módulos `stack/` a cada trimestre (plataformas mudam rápido — a Supabase trocou o modelo de API keys em ~1 ano); `core/` ao menos 1×/ano e a cada nova edição OWASP/CWE.
- **A norma é verificada como código:** todo push roda [o CI](.github/workflows/ci.yml) — links íntegros, matriz OWASP consistente com o frontmatter, limites de tamanho e **compilação de todos os Padrões prontos** (`deno check` com os tipos reais de zod/supabase/dompurify). Padrão que não compila não entra na norma. O repo também roda o próprio secret scan do [P4](core/secrets-config.md).
- Este é um playbook **opinativo e curado**: contribuições externas não são aceitas para preservar a integridade das normas. Encontrou um erro? Abra uma issue.
- Quando sair nova edição da OWASP Top 10, tags e matriz são atualizadas.

## 📄 Licença

[CC BY-ND 4.0](LICENSE.md) — use e compartilhe com atribuição; não redistribua versões modificadas. **Exceção:** os trechos de código dos módulos são MIT — copie e adapte livremente nos seus projetos. Detalhes em [LICENSE.md](LICENSE.md).

---

*Criado por [Silas Marques](https://github.com/silasmarques), 2026.*
