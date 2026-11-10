# Explorador

> Procura falhas reais num projeto existente e devolve, para cada uma: o que foi visto, com que grau de certeza, por que importa e como corrigir. Não substitui um pentest nem um scanner comercial — cobre bem um recorte estreito, e diz com clareza onde o recorte termina.

## Duas metades

| | Varredura (`deno task explore`) | Caça com roteiro ([hunts/](hunts/)) |
|---|---|---|
| Quem faz | código determinístico | uma IA (ou pessoa) seguindo o roteiro |
| Acha | falhas de **padrão**: RLS desligada, policy aberta, função privilegiada exposta, segredo no código, config frouxa | falhas de **lógica**: IDOR numa função, IA sem cap, prompt injection, corrida, fluxo fora de ordem |
| Certeza | reproduzível: mesma entrada, mesma saída | depende de quem executa — por isso o [protocolo de evidência](PROTOCOLO.md) |
| Medida | 45 de 45 falhas de padrão da [cobaia](../lab/README.md), zero iscas acusadas (teste de regressão no CI) | 7 falhas de lógica da cobaia: medidas por `eval/run-audit.ts`, fora do CI |

As duas se completam: a varredura entrega os fatos baratos e aponta suspeitos; a caça confirma ou descarta os suspeitos e procura o que nenhuma regra descreve.

## Rodar

```bash
deno task explore ../meu-projeto                      # relatório no terminal
deno task explore ../meu-projeto --md relatorio.md    # e em arquivo
deno task explore ../meu-projeto --json achados.json --quiet
```

Código de saída: `0` nada de CRÍTICO/ALTO confirmado e análise completa · `1` há CRÍTICO/ALTO confirmado · `2` **análise incompleta** (alguma migration não aplicou) — nesse caso o resultado não é um "limpo", e o relatório lista o que ficou de fora.

Só leitura: não altera o projeto analisado, não lê arquivos `.env*` e nunca copia um segredo inteiro para o relatório.

## Como funciona

**Núcleo universal — qualquer projeto JS/TS.** Regras sobre código e configuração ([code-checks.ts](code-checks.ts)). Quase tudo sai como **suspeito**: um padrão de texto não entende contexto, e o relatório não finge que entende. Sai **confirmado** só o que é fato de arquivo (não há lockfile; o `.gitignore` não cobre `.env`).

**Adaptador de banco — hoje, Supabase/Postgres** ([supabase/](supabase/)). As migrations do projeto são aplicadas, em ordem, num Postgres real que roda dentro do processo (PGlite), com um dublê mínimo de `auth` e `storage`. Os achados são lidos do **catálogo** — o estado em que o banco ficou — e não de regex sobre o SQL. Consequência prática: uma tabela criada sem RLS e corrigida três migrations depois não é acusada; uma RLS desligada por migration posterior, é. Achado de catálogo sai **confirmado**.

**Da suspeita à prova.** [supabase/probe.ts](supabase/probe.ts) abre o mesmo banco para você (ou a IA) executar SQL como anônimo, como um usuário e como o servidor. É assim que "usuário pode escrever em `profiles.role`" vira "o usuário se promoveu a admin" — há dois exemplos executáveis no fim de [scan.test.ts](scan.test.ts).

Projeto sem pasta `supabase/`: o núcleo roda inteiro e o relatório declara que o banco não foi analisado. Para outra stack de banco, escreve-se outro adaptador — o núcleo não muda.

## Regras

| Regra | Sev. | Estado | O que acusa |
|---|---|---|---|
| `DB-RLS-OFF` | CRÍTICO | confirmado | tabela do schema exposto sem RLS |
| `DB-POLICY-TRUE` | CRÍTICO/ALTO | confirmado | policy sem condição (`true`) para clientes |
| `DB-POLICY-USER-METADATA` | ALTO | confirmado | policy decide por `user_metadata` |
| `DB-VIEW-NO-INVOKER` | ALTO | confirmado | view exposta sem `security_invoker` |
| `DB-DEFINER-SEARCH-PATH` | ALTO | confirmado | `SECURITY DEFINER` sem `search_path` fixo |
| `DB-DEFINER-ANON-EXEC` | MÉDIO | confirmado | `SECURITY DEFINER` executável por anônimo |
| `DB-DEFINER-ID-PARAM` | ALTO | suspeito | `SECURITY DEFINER` recebe a identidade por parâmetro |
| `DB-COLUMN-WRITABLE` | ALTO | suspeito | usuário pode escrever em coluna de poder (papel, plano, saldo) |
| `DB-POLICY-NO-INDEX` | MÉDIO | confirmado | coluna de policy sem índice |
| `DB-BUCKET-PUBLIC` | MÉDIO | suspeito | bucket de storage público |
| `DB-RLS-NO-POLICY` · `DB-POLICY-NO-INITPLAN` · `DB-DEFINER-PG-TEMP` | BAIXO | confirmado | uma trava só; `auth.uid()` por linha; `search_path` sem `pg_temp` |
| `C-SECRET-HARDCODED` · `C-SECRET-IN-BUNDLE` | CRÍTICO | suspeito | segredo no código; credencial administrativa no frontend |
| `C-FETCH-DYNAMIC-URL` | ALTO | suspeito | chamada de rede para destino dinâmico sem validação SSRF |
| `C-IDENTITY-FROM-BODY` · `C-JWT-UNVERIFIED` · `C-GETSESSION-SERVER` | ALTO | suspeito | identidade vinda do request; token sem verificação |
| `C-SQL-CONCAT` · `C-SQL-DYNAMIC-EXEC` | ALTO | suspeito | SQL montado por concatenação |
| `C-DANGEROUS-HTML` · `C-REHYPE-RAW` · `C-OPEN-REDIRECT` | ALTO | suspeito | HTML dinâmico; redirect por parâmetro |
| `C-ENV-FALLBACK` | ALTO | suspeito | segredo com valor padrão |
| `C-CORS-WILDCARD` · `C-ERROR-LEAK` · `C-LOG-SENSITIVE` · `C-LIMIT-FROM-CLIENT` · `C-FETCH-NO-TIMEOUT` · `C-MATH-RANDOM` · `C-STORAGE-SECRET` | MÉDIO | suspeito | — |
| `C-EMPTY-CATCH` | BAIXO | suspeito | falha engolida |
| `CFG-GITIGNORE-ENV` | ALTO | confirmado | `.env` fora do `.gitignore` |
| `CFG-NO-LOCKFILE` · `CFG-NO-CSP` · `CFG-WORKFLOW-PERMISSIONS` | MÉDIO | confirmado | — |
| `CFG-VERIFY-JWT-OFF` | MÉDIO | suspeito | função sem verificação de token da plataforma |
| `CFG-ACTION-UNPINNED` · `CFG-TS-NOT-STRICT` | BAIXO | confirmado | — |

Cada regra de linha tem caso que dispara e caso que se cala, em [scan.test.ts](scan.test.ts).

## Exceção registrada

Achado que é decisão consciente fica silenciado **no ponto do código**, com o motivo — e reaparece numa seção própria do relatório, para ser revisto:

```typescript
// playbook-ignore: C-CORS-WILDCARD endpoint público de status, sem autenticação e sem dado de usuário
"Access-Control-Allow-Origin": "*",
```

O motivo é obrigatório (mínimo de 10 caracteres). Sem motivo, o achado continua aparecendo.

## Limites — o que isto NÃO faz

- **Falhas de lógica** ficam fora da varredura. Para elas, os roteiros de [hunts/](hunts/).
- **O banco analisado é o das migrations.** O que foi feito direto no painel não aparece. Se o schema inicial nasceu no painel, parte das migrations não aplica — o relatório lista quais, e a análise sai marcada como parcial. Em dois projetos reais em produção usados para calibrar o explorador, isso aconteceu com 14% e 38% das migrations.
- **O dublê não é a Supabase.** Extensões que não existem no Postgres de análise (`pg_net`, `pg_cron`, vault) fazem a migration falhar — de novo, declarado no relatório.
- **Só JS/TS e SQL.** Outras linguagens não são lidas.
- **Regra de texto erra para os dois lados.** Nos mesmos dois projetos, as regras de código produziram dezenas de suspeitos que exigem triagem; por isso são *suspeitos*.
- **Histórico do git, dependências vulneráveis e o ambiente publicado** não são analisados: use gitleaks, `npm audit`/OSV e os verificadores da plataforma.
- **Não ataca nada.** Não envia requisição ao seu sistema nem a terceiros.

## Acrescentar um adaptador

1. Criar `explore/<stack>/` com uma função que devolve `Finding[]` (tipos em [types.ts](types.ts)).
2. Chamá-la em [scan.ts](scan.ts) quando a stack for detectada.
3. Plantar as falhas correspondentes na cobaia (ou numa cobaia nova) e registrá-las no gabarito — sem isso, não há como saber se o adaptador funciona.
