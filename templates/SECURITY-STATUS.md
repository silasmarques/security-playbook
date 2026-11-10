# Estado de Segurança — <nome do projeto>

> Copie este arquivo para a raiz do projeto como `SECURITY-STATUS.md` e mantenha-o no git. É o registro do que foi verificado, do que está fora da norma e do que foi aceito como exceção — para que a próxima auditoria (e a próxima pessoa, ou IA) parta de fatos, não de memória.

- **Norma adotada:** security-playbook, versão/commit: `________`
- **Stack:** `________`
- **Modelo de isolamento:** por usuário · por organização · ambos (`secure-design` R4)

## Última exploração

| Data | Quem rodou | Comando | Cobertura | Resultado |
|---|---|---|---|---|
| AAAA-MM-DD | | `deno task explore <projeto>` | N migrations aplicadas, M falharam; K arquivos | X confirmados, Y suspeitos |

Relatório completo: `________` (não commitar relatório que contenha dado sensível).

## Achados em aberto

| # | Severidade | Status | Regra | Onde | Decisão | Prazo | Responsável |
|---|---|---|---|---|---|---|---|
| 1 | CRÍTICO | confirmado | `DB-RLS-OFF` | `public.pagamentos` | corrigir | | |

Status: **confirmado** (observado no artefato, ou provado com teste) · **suspeito** (aguardando triagem) · **descartado** (com o motivo).

## Exceções aceitas

Toda exceção tem dono, motivo e data de revisão. No código, a mesma exceção aparece como `playbook-ignore: <REGRA> <motivo>` no ponto exato.

| Regra | Onde | Motivo | Quem decidiu | Decidido em | Revisar em |
|---|---|---|---|---|---|
| | | | | | |

## Fora do alcance da verificação automática

O que NÃO foi coberto e precisa de outro meio (painel da plataforma, pentest, revisão humana):

- [ ] Configuração feita direto no painel (Auth, limites, buckets, chaves)
- [ ] Segredos no histórico do git (rodar gitleaks)
- [ ] Falhas de lógica — caçadas com os roteiros de `explore/hunts/`: `________`
- [ ] `________`

## Inventário de segredos

| Nome | Onde vive | Para que serve | Como rotacionar | Rotacionável? Se não: onde estão as 2 cópias e quando a restauração foi testada |
|---|---|---|---|---|
| | | | | |

## Histórico

| Data | O que mudou |
|---|---|
| | |
