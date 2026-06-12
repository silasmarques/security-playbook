---
last-review: 2026-06-11
sources:
  - https://owasp.org/Top10/2025/
---

# Matriz de Rastreabilidade — OWASP Top 10:2025

> Matriz inversa: para cada categoria da OWASP Top 10:2025, onde o playbook a cobre. Uso: auditoria de cobertura ("mostre minha cobertura de A03") e garantia de que nada do Top 10 ficou descoberto. As tags `owasp:` no frontmatter de cada módulo são a fonte da verdade — esta matriz é o índice delas.

| # | Categoria (2025) | Módulos | Inegociáveis | Como é coberta |
|---|---|---|---|---|
| A01 | Broken Access Control | [core/authorization.md](core/authorization.md) · [stack/supabase-rls.md](stack/supabase-rls.md) · [core/api-security.md](core/api-security.md) · [stack/edge-functions-deno.md](stack/edge-functions-deno.md) · [stack/ai-llm-security.md](stack/ai-llm-security.md) | #2, #3, #4, #10, #11 | Deny by default, checagem server-side centralizada, anti-IDOR, RLS por `auth.uid()`, SSRF (absorvido pelo A01 em 2025) e caps de uso. |
| A02 | Security Misconfiguration | [core/secrets-config.md](core/secrets-config.md) · [core/api-security.md](core/api-security.md) · [core/frontend-security.md](core/frontend-security.md) · [stack/edge-functions-deno.md](stack/edge-functions-deno.md) | #1, #14 | Secrets fora do código/bundle, separação por ambiente, security headers, CORS por allowlist, prod com debug off. |
| A03 | Software Supply Chain Failures | [core/dependencies-supply-chain.md](core/dependencies-supply-chain.md) | #12 | Lockfile + `npm ci`, audit no CI, 5 perguntas para dependência nova, anti-typosquatting/slopsquatting, CI com permissões mínimas. |
| A04 | Cryptographic Failures | [core/crypto-data-protection.md](core/crypto-data-protection.md) | #9 | AES-256-GCM com IV único, CSPRNG, comparações timing-safe, hash vs criptografia, chaves em env, formato versionado. |
| A05 | Injection | [core/input-validation.md](core/input-validation.md) · [core/frontend-security.md](core/frontend-security.md) · [stack/ai-llm-security.md](stack/ai-llm-security.md) · [stack/react-typescript.md](stack/react-typescript.md) | #5, #6, #15 | Schema na fronteira, queries parametrizadas, XSS via wrapper sanitizado único, prompt injection com defesa em camadas. |
| A06 | Insecure Design | Transversal: Bloco 1 do [SECURITY.md](SECURITY.md) · [checklists/new-feature.md](checklists/new-feature.md) (threat model) · [checklists/new-project.md](checklists/new-project.md) · [stack/react-typescript.md](stack/react-typescript.md) | todas | Sem módulo próprio por decisão de design: segurança nasce no desenho via 5 perguntas de ameaça antes de codar + setup seguro de projeto + tipos estritos. |
| A07 | Authentication Failures | [core/authentication.md](core/authentication.md) | #3 | Provedor estabelecido, JWT validado no servidor (`getUser`), erros sem enumeração, rate limit em credenciais, tokens single-use. |
| A08 | Software or Data Integrity Failures | [core/dependencies-supply-chain.md](core/dependencies-supply-chain.md) | #12 | SRI em CDN, lockfile como atestado de integridade, review humano em updates automatizados, artefatos de CI com permissões mínimas. |
| A09 | Security Logging and Alerting Failures | [core/logging-monitoring.md](core/logging-monitoring.md) | #13 | Eventos de segurança estruturados, redação automática de sensíveis, anti log-injection, `audit_log` persistente, alerta minimamente viável. |
| A10 | Mishandling of Exceptional Conditions | [core/error-handling-resilience.md](core/error-handling-resilience.md) · [core/api-security.md](core/api-security.md) | #7, #8 | Fail closed, sem vazamento de internals, timeouts obrigatórios, retry disciplinado, abort em estado impossível, tetos de recurso. |

## Notas de versão (2021 → 2025)

- **SSRF** deixou de ser categoria própria (A10:2021) e foi **absorvido pelo A01** — coberto em [core/authorization.md](core/authorization.md) R6/P2.
- **Software Supply Chain Failures (A03)** é nova (evolução de "Vulnerable and Outdated Components"), refletindo ataques a pacotes/pipelines — por isso o módulo dedicado.
- **Mishandling of Exceptional Conditions (A10)** é nova — por isso `error-handling-resilience.md` existe como módulo de primeira classe, coisa rara em guias.
- Verificação de consistência: as tags de frontmatter podem ser auditadas com
  `Get-ChildItem core,stack -Filter *.md | Select-String "^owasp:"` — o resultado deve bater com esta matriz.
