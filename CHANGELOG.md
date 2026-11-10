# Histórico de versões

## v2.0.0 — 2026-11-10 · a norma provada

A v1 dizia o que fazer. A v2 parte de um princípio novo — **nada entra na norma sem um teste que falha quando o padrão está quebrado** — e, ao aplicá-lo, encontrou e corrigiu erros da própria v1.

### Novo

- **[kit/](kit/README.md)** — os "Padrões prontos" viraram código real e testado, em duas camadas: `kit/web/` (universal, só APIs padrão da web) e `kit/supabase/` (SQL, guardas e template de função). Instalador: `kit/install.ts`.
- **[explore/](explore/README.md)** — varredura de projetos existentes (código, configuração e, na Supabase, o catálogo do banco após aplicar as migrations), com achados **confirmados** ou **suspeitos**; bancada de prova; [protocolo de evidência](explore/PROTOCOLO.md) e cinco roteiros de caça.
- **[lab/](lab/README.md)** — app-cobaia com 52 falhas plantadas, 12 iscas e gabarito.
- **[core/secure-design.md](core/secure-design.md)** — arquitetura: fronteiras de confiança, classificação de dados, modelo de ameaças, isolamento, ciclo de vida do dado pessoal, recuperação e incidente.
- **[templates/SECURITY-STATUS.md](templates/SECURITY-STATUS.md)** — registro de adoção por projeto.
- **CI que consegue falhar** — sincronização norma↔kit, referências cruzadas, contagens, e teste de mutação (43 controles quebrados de propósito).
- **[eval/run-audit.ts](eval/run-audit.ts)** — mede se uma IA encontra as falhas da cobaia.

### Erros da v1 corrigidos

Cada um destes estava publicado como padrão a copiar.

| Onde | O erro | Como foi constatado |
|---|---|---|
| authorization P2 (SSRF) | A checagem de IP era um comentário: `169.254.169.254` e `127.0.0.1` eram aceitos | executando o bloco |
| api-security P2 (rate limit) | Tabela de contadores **sem RLS** (violava a inegociável 2); janela ignorada; função privilegiada recebia o id do usuário por parâmetro, sem `REVOKE` | leitura + teste em Postgres |
| supabase-rls R2 | Afirmava que UPDATE sem `WITH CHECK` deixa transferir o registro. **Falso:** o Postgres reaproveita o `USING`. A brecha real é outra — escrita em coluna de poder —, agora R9/P5 | teste em Postgres |
| edge-functions P2 (CORS) | Origem fora da allowlist recebia `"null"`, que libera iframe em sandbox | documentação MDN |
| logging P2 (auditoria) | Insert ignorava o erro e a tabela não tinha como receber escrita do cliente: a trilha falhava em silêncio | leitura + teste |
| ai-llm P1 | O conteúdo podia conter o marcador de fim e "fechar" o bloco de dados | executando o bloco |
| ai-llm P2 | `\b` do JavaScript é ASCII: "você agora é…" nunca era detectado; texto comum de QA era | executando o bloco |
| crypto P1 | `btoa(String.fromCharCode(...bytes))` estourava a pilha acima de ~100 KB; sem id de chave, rotação era inviável | executando o bloco |
| api-security R1 × P1 | A regra e o padrão davam ordens diferentes para o prólogo | leitura |
| edge-functions P1 | O template não enviava security headers (inegociável 14); o 500 saía sem CORS | leitura |
| authentication P3 | Mínimo de 8 caracteres para senha; a NIST SP 800-63B-4 exige 15 quando a senha é o único fator | fonte oficial |
| eval/run-adoption.ts | Só rodava em Windows; a rubrica aceitava comentário e reporte como se fossem código | executando |
| pre-commit, secrets-config, owasp-mapping | Comandos só de PowerShell | leitura |
| CI | Aprovava helper com nome errado, SQL inválido e referência a regra inexistente | teste de mutação |

### Mudanças que pedem atenção ao atualizar

- `check_and_increment` mudou de assinatura: recebe só o nome da ação; limite e janela ficam na tabela `rate_limits`.
- O formato cifrado passou de `aes256gcm:<dados>` (chave derivada por PBKDF2) para `aesgcm1.<idDaChave>.<dados>` (chave de 32 bytes, com contexto). Migração: `crypto-data-protection` P1.
- `wrapUntrustedContent` emite marcadores com id aleatório; a instrução defensiva mudou junto.
- Inegociáveis: passaram de 16 para 17 (campo de poder e operação atômica); várias foram precisadas.

### Não verificado nesta versão

- As suítes com IA (`eval/run-adoption.ts`, `eval/run-audit.ts`) foram reescritas e a pontuação está testada, mas **não foram executadas** depois da reescrita. Os resultados da v1.2 não valem para a v2.

## v1.2 e anteriores

v1.2 (2026-07): CI de documentação e suíte de adoção. v1.1 (2026-07): CSRF, agentic-security, cooldown de dependências, CWE Top 25. v1.0 (2026-06): 10 módulos core, 4 de stack, checklists e matriz OWASP.
