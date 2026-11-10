# 🛡️ Security Playbook

**Um padrão de segurança para começar um projeto, para trazer um projeto existente ao padrão, e para procurar as falhas reais que ele tem — feito para ser usado por pessoas e por IAs de codificação (Claude Code, Cursor, Copilot e afins).**

> **Princípio:** nada entra na norma sem um teste que falha quando o padrão está quebrado.
> Pensar como atacante, documentar como defensor, provar como engenheiro.

São três peças que se sustentam:

| | O que é | Para quê |
|---|---|---|
| 📖 **Norma** | [SECURITY.md](SECURITY.md) + [core/](core/) + [stack/](stack/) | Regras objetivas (MUST/NEVER), anti-padrões com o ataque explicado, checklists. Rastreável à OWASP Top 10:2025. |
| 🧰 **Kit** | [kit/](kit/README.md) | O código que a norma manda escrever, já escrito e testado. Instala num projeto com um comando. |
| 🔎 **Explorador** | [explore/](explore/README.md) | Varredura que aponta falhas num projeto existente, com evidência — e roteiros de caça para o que só raciocínio encontra. |

**Em números:** 17 regras inegociáveis · 12 módulos [core/](core/) · 5 de [stack/](stack/) · 35 blocos de código da norma copiados do kit por script · 202 testes · 43 controles quebrados de propósito a cada push, todos detectados · cobaia com 52 falhas plantadas.

**Neste README:** [Os três usos](#-os-três-usos) · [O que é universal](#-o-que-é-universal-e-o-que-depende-da-stack) · [O que é garantido](#-o-que-é-garantido--e-como) · [Limites](#-limites--o-que-isto-não-é) · [Estrutura](#-estrutura) · [Manutenção](#-manutenção) · [Licença](#-licença)

---

## 🚀 Os três usos

Pré-requisito único: [Deno](https://deno.com) 2.x e um clone deste repositório.

```bash
git clone https://github.com/silasmarques/security-playbook.git
```

### 1. Começar um projeto no padrão

```bash
# a partir do clone do playbook
deno run --allow-read --allow-write kit/install.ts ../meu-projeto --sql
```

Isso entrega, testados: validação SSRF, CORS por allowlist, respostas com security headers, boundary de erro, criptografia com rotação de chave, logger com redação, validação de upload, e — na stack Supabase — tabela de perfil com privilégio por coluna, rate limit, auditoria append-only e o template de função com o prólogo completo. Depois, siga [checklists/new-project.md](checklists/new-project.md).

### 2. Fazer a IA seguir o padrão enquanto o código nasce

Cole este bloco no arquivo de regras da sua IA (Claude Code: `CLAUDE.md` · Cursor: `.cursorrules` · Copilot: `.github/copilot-instructions.md`), ajustando o caminho:

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

| Você diz | A IA faz |
|---|---|
| "Cria a tabela de comentários" | Migration com RLS, policies por operação e índice ([supabase-rls](stack/supabase-rls.md) P1) |
| "Adiciona busca por URL externa" | `safeFetch`: validação SSRF, timeout, redirect revalidado ([authorization](core/authorization.md) P2) |
| "Integra com a API do Gemini" | Rate limit e cap de custo ANTES da chamada ([ai-llm-security](stack/ai-llm-security.md)) |
| "Analisa essa feature antes de eu codar" | Modelo de ameaças + critérios de aceite ([prompts/pre-implementation.md](prompts/pre-implementation.md)) |
| "Consulta o playbook e revisa esse diff" | Relatório por achado, cada um **confirmado** ou **suspeito** ([prompts/security-review.md](prompts/security-review.md)) |

### 3. Explorar um projeto que já existe

```bash
deno task explore ../meu-projeto --md relatorio.md
```

Em segundos: tabelas sem RLS, policies abertas, funções privilegiadas expostas, colunas de poder que o usuário consegue escrever, segredos no código, configuração frouxa — cada achado com onde, evidência, por que importa e como corrigir. O relatório começa dizendo **o que foi analisado e o que não foi**. Não altera o projeto, não lê `.env`, não envia nada para fora.

Para as falhas que nenhuma regra descreve (IDOR dentro de uma função, IA sem limite, corrida de créditos), o roteiro completo está em [checklists/audit.md](checklists/audit.md), com um prompt pronto. O resultado fica registrado no projeto, em `SECURITY-STATUS.md` ([modelo](templates/SECURITY-STATUS.md)).

**Sem IA:** os checklists ([new-project](checklists/new-project.md), [new-feature](checklists/new-feature.md), [pre-commit](checklists/pre-commit.md), [audit](checklists/audit.md)) e a tabela de roteamento do [SECURITY.md](SECURITY.md) funcionam do mesmo jeito para uma pessoa.

---

## 🧭 O que é universal e o que depende da stack

Segurança vale para todo projeto; **prova** depende do que o projeto usa. O playbook separa as duas coisas de propósito:

| Camada | Vale para | Conteúdo |
|---|---|---|
| **Núcleo universal** | qualquer sistema | [SECURITY.md](SECURITY.md), os 12 módulos de [core/](core/) — inclusive [desenho seguro](core/secure-design.md) (fronteiras de confiança, classificação de dados, modelo de ameaças, incidente) —, checklists, [roteiros de caça](explore/hunts/acesso-cruzado.md) e o [protocolo de evidência](explore/PROTOCOLO.md) |
| **Kit web** | qualquer runtime JS/TS (Deno, Node, Bun, Workers, navegador) | [kit/web/](kit/web/) — só APIs padrão da web, sem dependência |
| **Varredura de código e config** | qualquer projeto JS/TS | [explore/code-checks.ts](explore/code-checks.ts) |
| **Adaptador Supabase/Postgres** | projetos nessa stack | [stack/](stack/), [kit/supabase/](kit/supabase/), [explore/supabase/](explore/supabase/) — RLS e funções testadas num Postgres real; achados lidos do catálogo do banco |

Num projeto de outra stack, o núcleo se aplica inteiro; o que falta é a prova automática de banco, e o relatório do explorador **diz isso** em vez de fingir cobertura. Um adaptador novo entra sem mexer no núcleo ([como](explore/README.md#acrescentar-um-adaptador)).

---

## ✅ O que é garantido — e como

Cada linha é verificada a cada push, pelo comando indicado. `deno task ci` roda tudo.

| Garantia | Como é provada |
|---|---|
| O código mostrado na norma é o código testado | Os blocos de "Padrões prontos" são copiados do kit por script; o CI falha se divergirem (`deno task snippets`). Bloco que não vem do kit está marcado `ilustrativo`. |
| Os padrões funcionam | 202 testes. O SQL (RLS, privilégios, funções) roda contra um **Postgres real**; o validador SSRF tem um caso por forma de IP. |
| Os testes conseguem falhar | `deno task mutation` remove 43 controles, um por vez — a checagem de metadata do SSRF, o `REVOKE` da função, a policy de dono — e exige que a suíte perceba cada um. |
| O kit instalado funciona | Um teste instala o kit num projeto vazio, compila o template e passa o explorador nele: zero achados. |
| O explorador não regride | Contra a [cobaia](lab/README.md): acha as 45 falhas de padrão plantadas e não acusa nenhuma das 12 iscas. |
| A documentação é consistente | Links, referências cruzadas (`módulo Rn`), matriz OWASP ↔ tags, contagens anunciadas e cadência de revisão (`deno task docs`). |
| O repositório segue a própria norma | Lockfile, actions fixadas por SHA, permissões mínimas no CI, secret scan com histórico completo. |

---

## ⚠️ Limites — o que isto NÃO é

- **Não substitui pentest nem scanner comercial.** É um recorte estreito e fundo, com as bordas declaradas. Para sistema que guarda dinheiro ou dado sensível de terceiros, contrate um teste de invasão.
- **Não garante que um projeto está seguro.** Reduz risco e encontra muita coisa. "Zero achados" significa "nada do que foi procurado, no que foi analisado" — e o relatório lista os dois.
- **A prova de banco é sobre as migrations, com um dublê da Supabase.** O que foi feito direto no painel não aparece. Em dois projetos reais usados para calibrar o explorador, 14% e 38% das migrations não aplicaram no banco de análise; nesses casos o resultado sai marcado como parcial.
- **A varredura de código é por padrão de texto.** Erra para os dois lados; por isso quase tudo sai como *suspeito*, para triagem.
- **Falhas de lógica dependem de quem caça.** Os roteiros orientam; o resultado varia com a IA (ou a pessoa) que os executa.
- **As suítes com IA não rodam no CI** — custam tokens e variam a cada execução: [eval/run-adoption.ts](eval/run-adoption.ts) (a IA aplica o playbook sem ser lembrada?) e [eval/run-audit.ts](eval/run-audit.ts) (a IA acha as falhas da cobaia?). A pontuação delas é determinística e testada; os números de uma execução valem para aquele modelo, naquele dia. Ambas foram reescritas na v2 e **ainda não têm resultado publicado**.
- **Adaptador pronto: só Supabase/Postgres.** Mobile, outras linguagens e outros bancos têm a norma e os roteiros, não a prova automática.
- **O módulo de desenho seguro não é aconselhamento jurídico** (LGPD e afins).

---

## 📦 Estrutura

```text
security-playbook/
├── SECURITY.md        ← porta de entrada: 17 inegociáveis + roteamento + instruções p/ IA
├── core/              ← 12 módulos universais
├── stack/             ← 5 módulos de stack (Supabase, Deno, React/TS, IA, agentes)
├── kit/
│   ├── web/           ← helpers universais (SSRF, CORS, cripto, log, upload…)
│   ├── supabase/      ← SQL, guardas e template de função
│   ├── tests/         ← os testes de tudo acima
│   └── install.ts     ← instala o kit num projeto
├── explore/
│   ├── cli.ts         ← deno task explore <projeto>
│   ├── code-checks.ts ← núcleo universal: código e configuração
│   ├── supabase/      ← adaptador: banco via catálogo + bancada de prova
│   ├── PROTOCOLO.md   ← o que conta como evidência
│   └── hunts/         ← 5 roteiros de caça
├── lab/               ← cobaia vulnerável de propósito + gabarito
├── eval/              ← suítes com IA (adoção e auditoria) — fora do CI
├── checklists/        ← new-project · new-feature · pre-commit · audit
├── prompts/           ← análise pré-implementação · revisão de diff
├── templates/         ← SECURITY-STATUS.md (registro por projeto)
├── scripts/           ← verify-docs · sync-snippets · check-code-blocks · mutation-check
└── owasp-mapping.md   ← matriz OWASP Top 10:2025 ↔ CWE Top 25:2025
```

### Os módulos

**[core/](core/) — valem para qualquer stack:**
[authentication](core/authentication.md) · [authorization](core/authorization.md) (inclui SSRF e multi-tenant) · [api-security](core/api-security.md) · [input-validation](core/input-validation.md) · [secrets-config](core/secrets-config.md) · [crypto-data-protection](core/crypto-data-protection.md) · [dependencies-supply-chain](core/dependencies-supply-chain.md) · [frontend-security](core/frontend-security.md) · [error-handling-resilience](core/error-handling-resilience.md) · [logging-monitoring](core/logging-monitoring.md) · [security-testing](core/security-testing.md) · [secure-design](core/secure-design.md)

**[stack/](stack/) — a forma concreta numa stack:**
[supabase-rls](stack/supabase-rls.md) · [edge-functions-deno](stack/edge-functions-deno.md) · [react-typescript](stack/react-typescript.md) · [ai-llm-security](stack/ai-llm-security.md) · [agentic-security](stack/agentic-security.md)

Todo módulo segue o mesmo formato: **Regras → Padrões prontos → Anti-padrões → Checklist**.

---

## 🔧 Manutenção

```bash
deno task ci         # tudo o que o CI roda
deno task test       # só os testes
deno task docs       # consistência da documentação
deno task snippets   # norma idêntica ao kit?   (snippets:write reescreve)
deno task mutation   # os testes conseguem falhar?
```

- **Mudou um padrão?** Edite o arquivo do kit e o teste dele; `deno task snippets:write` atualiza a norma. Nunca edite o bloco direto no markdown — o CI desfaz.
- **Regra nova no explorador?** Primeiro plante a falha na cobaia e registre no gabarito ([lab/README.md](lab/README.md)).
- **Garantia nova?** Acrescente a mutação correspondente em [scripts/mutation-check.ts](scripts/mutation-check.ts).
- **Cadência de revisão:** módulos de `stack/` a cada trimestre, `core/` ao menos uma vez por ano e a cada nova edição OWASP/CWE. Um workflow semanal falha quando um módulo passa do prazo.
- **Afirmação sobre plataforma externa** (limites, nomes de chave, comportamento de API) cita a fonte e a data em que foi conferida — e envelhece. Reconfira antes de depender dela.
- Histórico de versões: [CHANGELOG.md](CHANGELOG.md). Playbook companheiro, para estratégia de testes: [testing-playbook](https://github.com/silasmarques/testing-playbook).
- Este é um playbook **opinativo e curado**: contribuições diretas não são aceitas. Encontrou um erro? Abra uma issue.

## 📄 Licença

[CC BY-ND 4.0](LICENSE.md) para a norma (texto, estrutura, regras). **Todo o código** — `kit/`, `explore/`, `scripts/`, `eval/` e os blocos de código dos módulos — é MIT: copie e adapte livremente. Detalhes em [LICENSE.md](LICENSE.md).

---

*Criado por [Silas Marques](https://github.com/silasmarques), 2026.*
