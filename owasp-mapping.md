---
last-review: 2026-07-02
sources:
  - https://owasp.org/Top10/2025/
  - https://cwe.mitre.org/top25/archive/2025/2025_cwe_top25.html
---

# Matriz de Rastreabilidade — OWASP Top 10:2025

> Matriz inversa: para cada categoria da OWASP Top 10:2025, onde o playbook a cobre. Uso: auditoria de cobertura ("mostre minha cobertura de A03") e garantia de que nada do Top 10 ficou descoberto. As tags `owasp:` no frontmatter de cada módulo são a fonte da verdade — esta matriz é o índice delas. A coluna CWE liga as fraquezas do **CWE Top 25:2025** (validado na fonte em 2026-07-02) à categoria onde o playbook as cobre.

| # | Categoria (2025) | Módulos | Inegociáveis | CWE Top 25:2025 | Como é coberta |
|---|---|---|---|---|---|
| A01 | Broken Access Control | [core/authorization.md](core/authorization.md) · [stack/supabase-rls.md](stack/supabase-rls.md) · [core/api-security.md](core/api-security.md) · [stack/edge-functions-deno.md](stack/edge-functions-deno.md) · [stack/ai-llm-security.md](stack/ai-llm-security.md) · [core/security-testing.md](core/security-testing.md) · [stack/agentic-security.md](stack/agentic-security.md) | #2, #3, #4, #10, #11 | CWE-352 (#3, CSRF) · CWE-862 (#4) · CWE-863 (#17) · CWE-284 (#19) · CWE-918 (#22, SSRF) · CWE-639 (#24, IDOR) · CWE-770 (#25) | Deny by default, checagem server-side centralizada, anti-IDOR, RLS por `auth.uid()`, SSRF (absorvido pelo A01 em 2025), caps de uso, defesa anti-CSRF condicional (api-security R9) e teste A×B (security-testing P1). |
| A02 | Security Misconfiguration | [core/secrets-config.md](core/secrets-config.md) · [core/api-security.md](core/api-security.md) · [core/frontend-security.md](core/frontend-security.md) · [stack/edge-functions-deno.md](stack/edge-functions-deno.md) | #1, #14 | CWE-200 (#20) | Secrets fora do código/bundle, secret scan manual + CI (secrets-config P3/P4), separação por ambiente, security headers, CORS por allowlist, prod com debug off. |
| A03 | Software Supply Chain Failures | [core/dependencies-supply-chain.md](core/dependencies-supply-chain.md) · [stack/agentic-security.md](stack/agentic-security.md) | #12 | — | Lockfile + `npm ci`, audit no CI, 5 perguntas para dependência nova, anti-typosquatting/slopsquatting, cooldown de release (R9), vetting de MCP servers (agentic-security P1), CI com permissões mínimas. |
| A04 | Cryptographic Failures | [core/crypto-data-protection.md](core/crypto-data-protection.md) | #9 | — | AES-256-GCM com IV único, CSPRNG, comparações timing-safe, hash vs criptografia, chaves em env, formato versionado. |
| A05 | Injection | [core/input-validation.md](core/input-validation.md) · [core/frontend-security.md](core/frontend-security.md) · [stack/ai-llm-security.md](stack/ai-llm-security.md) · [stack/react-typescript.md](stack/react-typescript.md) · [core/security-testing.md](core/security-testing.md) · [stack/agentic-security.md](stack/agentic-security.md) · [stack/edge-functions-deno.md](stack/edge-functions-deno.md) | #5, #6, #15 | CWE-79 (#1, XSS) · CWE-89 (#2, SQLi) · CWE-78 (#9) · CWE-94 (#10) · CWE-434 (#12, upload) · CWE-20 (#18) · CWE-77 (#23) | Schema na fronteira, queries parametrizadas, upload validado em 4 dimensões, XSS via wrapper sanitizado único, prompt injection com defesa em camadas — inclusive contra agentes de codificação (agentic-security R3) —, vetores de teste negativo (security-testing P2). |
| A06 | Insecure Design | Transversal: Bloco 1 do [SECURITY.md](SECURITY.md) · [checklists/new-feature.md](checklists/new-feature.md) (threat model) · [checklists/new-project.md](checklists/new-project.md) · [stack/react-typescript.md](stack/react-typescript.md) · [core/security-testing.md](core/security-testing.md) | todas | — | Sem módulo próprio por decisão de design: segurança nasce no desenho via 5 perguntas de ameaça antes de codar + setup seguro de projeto + tipos estritos + critérios de aceite em BDD defensivo (security-testing P4). |
| A07 | Authentication Failures | [core/authentication.md](core/authentication.md) | #3 | CWE-306 (#21) | Provedor estabelecido, JWT validado no servidor (`getUser`), erros sem enumeração, rate limit em credenciais, tokens single-use. |
| A08 | Software or Data Integrity Failures | [core/dependencies-supply-chain.md](core/dependencies-supply-chain.md) | #12 | — | SRI em CDN, lockfile como atestado de integridade, review humano em updates automatizados, artefatos de CI com permissões mínimas. |
| A09 | Security Logging and Alerting Failures | [core/logging-monitoring.md](core/logging-monitoring.md) | #13 | — | Eventos de segurança estruturados, redação automática de sensíveis, anti log-injection, `audit_log` persistente, alerta minimamente viável. |
| A10 | Mishandling of Exceptional Conditions | [core/error-handling-resilience.md](core/error-handling-resilience.md) · [core/api-security.md](core/api-security.md) · [stack/edge-functions-deno.md](stack/edge-functions-deno.md) | #7, #8 | — | Fail closed, sem vazamento de internals, timeouts obrigatórios, retry disciplinado, abort em estado impossível, tetos de recurso. |

**Leitura da coluna CWE:** curadoria própria — cada célula lista as fraquezas do CWE Top 25:2025 que o playbook cobre naquela categoria (com a posição no ranking). "—" significa que nenhuma fraqueza do Top 25 desta edição mapeia diretamente para a categoria **nesta stack** (memória insegura, por exemplo, não se aplica a TS/managed runtime) — a categoria segue coberta pelos módulos. Fraquezas do Top 25 fora do escopo da stack (buffer overflows CWE-787/121/122/125, use-after-free CWE-416, NULL deref CWE-476, deserialização CWE-502) não são mapeadas por decisão consciente, não por lacuna.

## Notas de versão (2021 → 2025)

- **SSRF** deixou de ser categoria própria (A10:2021) e foi **absorvido pelo A01** — coberto em [core/authorization.md](core/authorization.md) R6/P2.
- **Software Supply Chain Failures (A03)** é nova (evolução de "Vulnerable and Outdated Components"), refletindo ataques a pacotes/pipelines — por isso o módulo dedicado.
- **Mishandling of Exceptional Conditions (A10)** é nova — por isso `error-handling-resilience.md` existe como módulo de primeira classe, coisa rara em guias.
- **CSRF (CWE-352)** voltou ao top 3 do CWE Top 25 em 2025 — coberto pela regra condicional [core/api-security.md](core/api-security.md) R9 (v1.1).
- Verificação de consistência: as tags de frontmatter podem ser auditadas com
  `Get-ChildItem core,stack -Filter *.md | Select-String "^owasp:"` — o resultado deve bater com esta matriz.
