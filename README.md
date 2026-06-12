# 🛡️ Security Playbook

**Um norte de segurança normativo para desenvolvimento de software — feito para ser consumido por humanos e por IAs de codificação (Claude Code, Cursor, Copilot e afins).**

Serve aos dois momentos da vida de um sistema:

- **Construindo:** a IA (ou você) consulta o playbook enquanto o código nasce — e ele já nasce seguro.
- **Mantendo:** rode o [pente fino](checklists/audit.md) num sistema que já existe e descubra, com relatório priorizado, o que está fora dos conformes.

Não é material de estudo nem coletânea de boas práticas genéricas: é **norma operacional**. Regras objetivas (MUST/NEVER), padrões de código prontos para copiar, anti-padrões com o ataque explicado, e checklists verificáveis — tudo rastreável à **OWASP Top 10:2025**.

---

## 📦 O que tem dentro

### A porta de entrada

**[SECURITY.md](SECURITY.md)** — 15 regras inegociáveis + tabela de roteamento ("vou fazer X → leio Y") + instruções de como uma IA deve consultar e reportar conformidade. É o único arquivo que precisa estar sempre à mão; o resto é consultado sob demanda.

### 10 módulos universais — [core/](core/)

Valem para qualquer stack web:

| Módulo | Cobre |
|---|---|
| [authentication](core/authentication.md) | JWT validado no servidor, sessões, erros sem enumeração |
| [authorization](core/authorization.md) | Deny by default, anti-IDOR, checagem centralizada, SSRF |
| [input-validation](core/input-validation.md) | Schema na fronteira, queries parametrizadas, uploads |
| [secrets-config](core/secrets-config.md) | Onde mora cada chave, security headers, CORS |
| [crypto-data-protection](core/crypto-data-protection.md) | AES-256-GCM, HMAC timing-safe, CSPRNG |
| [dependencies-supply-chain](core/dependencies-supply-chain.md) | Lockfile, audit no CI, avaliação de dependência nova |
| [api-security](core/api-security.md) | Prólogo canônico de endpoint, rate limiting, erros padrão |
| [frontend-security](core/frontend-security.md) | XSS, CSP, sanitização centralizada, clickjacking |
| [error-handling-resilience](core/error-handling-resilience.md) | Fail closed, timeouts, retry disciplinado |
| [logging-monitoring](core/logging-monitoring.md) | Eventos de segurança, redação automática, audit log |

### 4 módulos de stack — [stack/](stack/)

Aplicação concreta em TypeScript/React/Supabase/Deno (princípios transferíveis para stacks equivalentes):

| Módulo | Cobre |
|---|---|
| [supabase-rls](stack/supabase-rls.md) | RLS como fronteira de dados, template de migration, Storage |
| [edge-functions-deno](stack/edge-functions-deno.md) | Template de função segura, helpers compartilhados, webhooks HMAC |
| [react-typescript](stack/react-typescript.md) | TS estrito como segurança, env validada, open redirect |
| [ai-llm-security](stack/ai-llm-security.md) ★ | Prompt injection em camadas, BYOK, RAG, caps de custo, tool-use |

★ Segurança de IA/LLM tratada como cidadã de primeira classe — o módulo mais difícil de encontrar pronto em outros guias.

### 4 checklists — [checklists/](checklists/)

| Checklist | Quando usar |
|---|---|
| [new-project](checklists/new-project.md) | Criando um projeto — segurança do dia 1 |
| [new-feature](checklists/new-feature.md) | Antes de codar uma feature — mini threat model em 5 perguntas |
| [pre-commit](checklists/pre-commit.md) | Antes de todo commit |
| [audit](checklists/audit.md) | Pente fino em sistema que já existe |

### A prova de cobertura

**[owasp-mapping.md](owasp-mapping.md)** — matriz que mapeia cada categoria da OWASP Top 10:2025 aos módulos e regras que a cobrem. Nada do Top 10 fica descoberto.

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
| "Consulta o playbook e revisa esse diff" | Consulta integral + checklist [pre-commit](checklists/pre-commit.md) |

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
- Este é um playbook **opinativo e curado**: contribuições externas não são aceitas para preservar a integridade das normas. Encontrou um erro? Abra uma issue.
- Quando sair nova edição da OWASP Top 10, tags e matriz são atualizadas.

## 📄 Licença

[CC BY-ND 4.0](LICENSE.md) — use e compartilhe com atribuição; não redistribua versões modificadas. **Exceção:** os trechos de código dos módulos são MIT — copie e adapte livremente nos seus projetos. Detalhes em [LICENSE.md](LICENSE.md).

---

*Criado por [Silas Marques](https://github.com/silasmarques), 2026.*
