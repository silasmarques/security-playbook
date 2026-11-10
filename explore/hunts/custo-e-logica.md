# Caça: abuso de custo e falhas de lógica

> A pergunta: **dá para usar mais do que se pagou, repetir o que devia acontecer uma vez, ou ganhar uma corrida contra o próprio sistema?** Nenhum scanner acha isto: o código está "certo" linha a linha e errado no conjunto. Norma: [api-security](../../core/api-security.md) R2/R8/R10, [error-handling-resilience](../../core/error-handling-resilience.md). Seguir o [protocolo de evidência](../PROTOCOLO.md).

## Inventário primeiro

Liste (1) toda operação que custa dinheiro por chamada (IA, e-mail, SMS, export, armazenamento); (2) todo recurso contável (crédito, cota, cupom, vaga, estoque, tentativa); (3) toda operação que deve acontecer uma vez só (pagamento, resgate, convite, confirmação); (4) todo fluxo em etapas (checkout, onboarding, aprovação).

## Hipóteses

### H1 — Operação cara sem limite por usuário
- **Procurar:** para cada item (1), existe checagem de limite ANTES do trabalho? O limite é definido no servidor?
- **Provar:** disparar o limite + 1 chamadas. Confirmado se todas passam.
- **Falso positivo:** limite aplicado em camada anterior (gateway, WAF) — então provar que ele vale para aquela rota.

### H2 — O limite existe, mas dá para contornar
- **Procurar:** contador que o cliente consegue zerar ou evitar (tabela sem isolamento, limite passado como argumento, identidade do contador vinda do request, janela reiniciada por parâmetro); limite por conta quando criar conta é grátis.
- **Provar:** estourar o limite, aplicar o contorno, e passar de novo.

### H3 — Checar e depois alterar (corrida)
- **Procurar:** leitura do saldo/cota, decisão no código, escrita depois — sem transação nem comando atômico.
- **Provar:** N requisições **em paralelo** com saldo para uma. Confirmado se mais de uma tem sucesso, ou se o saldo final não fecha.
- **Falso positivo:** o débito é um único `update … where saldo >= x`, ou há trava (`select … for update`) na mesma transação.

### H4 — Repetir a requisição repete o efeito
- **Procurar:** escrita crítica sem chave de idempotência; webhook processado sem guardar o id do evento.
- **Provar:** reenviar a mesma requisição (ou o mesmo evento). Confirmado se cobra, credita ou cria duas vezes.

### H5 — Pular etapa ou inverter a ordem
- **Procurar:** fluxo em que cada etapa confia que a anterior aconteceu, sem conferir o estado no servidor.
- **Provar:** chamar a última etapa direto; voltar a uma etapa já concluída.

### H6 — Valor que deveria ser do servidor vem do cliente
- **Procurar:** preço, quantidade, desconto, plano, limite de página aceitos do request. Regra `C-LIMIT-FROM-CLIENT`.
- **Provar:** enviar preço menor, quantidade negativa, `limit=10000000`.

### H7 — A falha abre em vez de fechar
- **Procurar:** `catch` que deixa seguir; checagem cujo erro é tratado como "ok"; dependência fora do ar virando "liberado". Regra `C-EMPTY-CATCH`.
- **Provar:** derrubar a dependência (ou simular o erro) e repetir a operação protegida.

### H8 — Chamada externa sem timeout
- **Procurar:** regra `C-FETCH-NO-TIMEOUT`.
- **Provar:** apontar para um destino que aceita a conexão e não responde; medir quanto tempo a rota fica presa.

## Correção

Limite no banco, contado para a identidade do token ([02_rate_limit.sql](../../kit/supabase/sql/02_rate_limit.sql)) · débito atômico (`api-security` P4) · idempotência · estado conferido no servidor · timeout e retry disciplinado ([resilience.ts](../../kit/web/resilience.ts)) · guardas fail-closed ([guards.ts](../../kit/supabase/guards.ts)).
