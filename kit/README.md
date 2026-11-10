# Kit

> O código que a norma manda escrever, já escrito e testado. Cada bloco de "Padrões prontos" dos módulos é copiado **destes arquivos** por um script — o que você lê na norma é exatamente o que os testes exercitam.

## Duas camadas

| Pasta | O que é | Depende de |
|---|---|---|
| [web/](web/) | **Universal.** Só APIs padrão da web (`fetch`, `URL`, `crypto.subtle`, `Request`/`Response`). Roda em Deno, Node 20+, Bun, Workers e navegador. | nada |
| [supabase/](supabase/) | **Adaptador Supabase/Postgres.** SQL (RLS, rate limit, auditoria), guardas que chamam essas funções e o template de Edge Function. | `web/` + SDK da Supabase (só o template) |

| Arquivo | Resolve | Norma |
|---|---|---|
| [web/ssrf.ts](web/ssrf.ts) | validação de URL de saída, fetch com redirect revalidado, corpo com teto | `authorization` R6 |
| [web/cors.ts](web/cors.ts) · [web/http.ts](web/http.ts) | CORS por allowlist; respostas com security headers; body com teto | `api-security` R7/R11 |
| [web/error-boundary.ts](web/error-boundary.ts) | erro genérico + requestId, sem vazar internals | `error-handling-resilience` R2 |
| [web/crypto.ts](web/crypto.ts) | AES-256-GCM com rotação e contexto; HMAC; payload assinado; token opaco | `crypto-data-protection` |
| [web/untrusted-content.ts](web/untrusted-content.ts) · [web/injection-risk.ts](web/injection-risk.ts) | delimitação de conteúdo externo em prompt; score de risco para RAG | `ai-llm-security` R1/R6 |
| [web/upload.ts](web/upload.ts) | upload validado pelo conteúdo, nome gerado no servidor | `input-validation` R4 |
| [web/log.ts](web/log.ts) | log estruturado com redação e anti log-injection | `logging-monitoring` R2–R4 |
| [web/resilience.ts](web/resilience.ts) | timeout em chamada externa; retry só transitório | `error-handling-resilience` R4/R5 |
| [web/env.ts](web/env.ts) | config obrigatória que falha o boot | `secrets-config` R8 |
| [web/safe-url.ts](web/safe-url.ts) | href seguro; redirect só interno | `frontend-security` R2 |
| [supabase/sql/](supabase/sql/) | perfil com privilégio por coluna, checagem de acesso, rate limit, auditoria append-only, tabela com dono, storage | `supabase-rls` |
| [supabase/guards.ts](supabase/guards.ts) | acesso, rate limit e auditoria — todas fail-closed | `authorization` R4 |
| [supabase/function-template/](supabase/function-template/) | Edge Function com o prólogo completo | `edge-functions-deno` P1 |

## Instalar num projeto

```bash
deno run --allow-read --allow-write kit/install.ts ../meu-projeto          # helpers + template
deno run --allow-read --allow-write kit/install.ts ../meu-projeto --sql    # + migrations
```

Copia os helpers para `supabase/functions/_shared/`, o template para `supabase/functions/_template/` (pasta com `_` não é publicada como função) e reescreve os imports. **Não sobrescreve arquivo que já existe** (use `--force` de propósito). `--sql` cria migrations com as tabelas `profiles`, `rate_limits`, `usage_counters`, `audit_log` e o exemplo `qa_notes` — leia antes de aplicar: pode colidir com o que o projeto já tem.

Em outra stack JS/TS, os arquivos de `web/` são autocontidos: copie os que precisar.

Depois de instalar: definir `ALLOWED_ORIGINS` nos secrets; cadastrar cada ação cara em `rate_limits`; copiar `_template` para cada função nova.

## Testes

```bash
deno task test    # tudo
deno test --allow-read --allow-env kit/tests/ssrf.test.ts
```

O SQL roda contra Postgres real (PGlite) com um dublê do ambiente Supabase — [supabase/supabase-shim.sql](supabase/supabase-shim.sql) diz exatamente o que o dublê reproduz e o que não. O dublê concede a `anon`/`authenticated` todos os privilégios em objeto novo: é o cenário mais permissivo, e o SQL do kit tem de se sustentar nele.

Garantias verificadas a cada push: o kit instalado num projeto vazio passa pelo explorador com **zero achados** e o template instalado **compila**; e, se um controle for removido, **algum teste falha** — `scripts/mutation-check.ts` quebra o kit de propósito, um controle por vez, e exige que a suíte perceba.

## O que os testes NÃO provam

- Que a Supabase real se comporta como o dublê. Prova-se a semântica do Postgres (RLS, GRANT, função); repita o teste A×B no seu projeto.
- Que o modelo de IA respeita a delimitação — só que o conteúdo não consegue forjá-la.
- Que `validateOutboundUrl` impede DNS rebinding — ela não impede; ver o cabeçalho do arquivo.
- Que o score de risco pega paráfrase ou outro idioma — os testes fixam que **não** pega.
