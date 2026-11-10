# Caça: acesso cruzado e escalada de privilégio

> A pergunta: **um usuário consegue ler, alterar ou agir sobre o que é de outro — ou virar o que não é?** É a classe mais comum e mais grave (OWASP A01). Norma: [authorization](../../core/authorization.md), [supabase-rls](../../stack/supabase-rls.md). Seguir o [protocolo de evidência](../PROTOCOLO.md).

## Inventário primeiro

Liste, lendo o projeto: (1) todo recurso que tem dono (tabelas, arquivos, registros); (2) todo ponto que recebe um identificador vindo de fora (rota, body, query, nome de arquivo); (3) todo lugar onde o código usa credencial que ignora o isolamento (chave de serviço, conexão administrativa, função privilegiada no banco); (4) todo campo que define poder (papel, plano, saldo, bloqueio, organização).

## Hipóteses

### H1 — Buscar pelo id de outro devolve o recurso (IDOR)
- **Procurar:** consultas por id sem filtro de dono; e, com mais atenção, as que usam credencial privilegiada — ali o banco não barra nada.
- **Provar:** dois usuários de teste; A cria; B pede o id de A. Confirmado se B recebe o conteúdo. Conferir também editar e apagar.
- **Falso positivo:** o filtro existe em camada mais baixa (isolamento no banco, com o client do próprio usuário). Verificar qual credencial faz a consulta antes de descartar.

### H2 — O isolamento no banco tem buraco
- **Procurar:** rode `deno task explore <projeto>`. Regras `DB-RLS-OFF`, `DB-POLICY-TRUE`, `DB-VIEW-NO-INVOKER`, `DB-DEFINER-*`.
- **Provar:** com a bancada, executar como B (ou como anônimo) a leitura/escrita que não deveria passar — exemplos em [scan.test.ts](../scan.test.ts), testes "PROVA executável".
- **Falso positivo:** dado público de propósito. Então é exceção a registrar, não achado a ignorar.

### H3 — Editar o próprio registro permite mexer em campo de poder
- **Procurar:** regra `DB-COLUMN-WRITABLE`; e, no código, updates que repassam o body inteiro.
- **Provar:** como usuário comum, `update` do próprio registro definindo o papel/plano/saldo. Confirmado se o valor muda.
- **Falso positivo:** a policy de UPDATE só admite administradores (ler a condição); ou há gatilho que reverte o campo.

### H4 — A identidade vem de onde o usuário escreve
- **Procurar:** id de usuário, organização ou papel lido de body, query, header, `user_metadata`; token decodificado sem verificar assinatura; sessão lida do armazenamento local em código de servidor. Regras `C-IDENTITY-FROM-BODY`, `C-JWT-UNVERIFIED`, `C-GETSESSION-SERVER`, `DB-POLICY-USER-METADATA`, `DB-DEFINER-ID-PARAM`.
- **Provar:** repetir a chamada trocando o identificador por outro; ou forjar a claim. Confirmado se o servidor age em nome do outro.
- **Falso positivo:** o valor do request é só comparado com a identidade verificada (e a divergência é recusada).

### H5 — Alguma rota ficou sem autenticação ou sem a checagem central
- **Procurar:** percorrer TODAS as rotas e marcar, para cada uma: autentica? chama a checagem de acesso? Rota sem verificação de token da plataforma (`CFG-VERIFY-JWT-OFF`) precisa provar a identidade de outro jeito.
- **Provar:** chamar sem token, com token de usuário bloqueado e com token de outro papel.
- **Falso positivo:** rota pública de propósito (status, página de login) que não toca dado de usuário.

### H6 — Trocar de organização é trocar um parâmetro
- **Procurar:** em sistema com times/organizações, de onde vem o id da organização em cada consulta.
- **Provar:** usuário da organização X pede recurso da Y. Confirmado se recebe.

## Correção

Filtro de dono em toda consulta por id + isolamento no banco ([04_owned_table_template.sql](../../kit/supabase/sql/04_owned_table_template.sql)) · privilégio por coluna ([01_profiles_access.sql](../../kit/supabase/sql/01_profiles_access.sql)) · checagem central fail-closed ([guards.ts](../../kit/supabase/guards.ts)) · e o teste A×B que prova, com controle positivo.
