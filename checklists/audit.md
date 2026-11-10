---
owasp: [A01, A02, A03, A04, A05, A06, A07, A08, A09, A10]
last-review: 2026-11-10
---

# Checklist: Explorar um Sistema Existente

> Para quando o sistema JÁ existe e você quer saber onde ele quebra. O roteiro começa pelo que é barato e certo (varredura), passa pelo que exige raciocínio (caça), e termina num registro que fica no projeto. Regra do começo ao fim: [protocolo de evidência](../explore/PROTOCOLO.md) — nada é "provavelmente vulnerável", e todo relatório diz o que **não** foi analisado.

## Etapa 0 — Varredura (minutos, reproduzível)

- [ ] Rodar `deno task explore <projeto> --md relatorio.md` a partir do clone do playbook
- [ ] Ler a seção **Cobertura** antes dos achados: quantas migrations aplicaram? Alguma falhou? O banco foi analisado?
- [ ] Código de saída `2` = análise incompleta: o resultado não é um "limpo"

## Etapa 1 — Inventário (mapear a superfície)

Sem inventário, a exploração só olha o que lembra.

- [ ] **Endpoints/funções:** todos os handlers HTTP — nome, o que fazem, como autenticam
- [ ] **Dados:** tabelas, buckets e a classe de cada um (`secure-design` P2)
- [ ] **Entradas:** forms, uploads, webhooks, integrações que RECEBEM dados
- [ ] **Saídas:** APIs de terceiros, fetches dinâmicos, chamadas a modelos de IA — e o custo de cada uma
- [ ] **Segredos:** todas as chaves e ONDE vivem
- [ ] **Recursos contáveis e operações de uma vez só:** créditos, cotas, pagamentos, convites

## Etapa 2 — Triagem dos suspeitos

- [ ] Cada **suspeito** da varredura vira **confirmado** (com prova) ou **descartado** (com motivo)
- [ ] Suspeito de banco: provar na bancada ([explore/supabase/probe.ts](../explore/supabase/probe.ts)) executando como outro usuário
- [ ] Exceção legítima: registrar no código (`playbook-ignore: <REGRA> <motivo>`) e no `SECURITY-STATUS.md`

## Etapa 3 — Caça por classe (o que a varredura não vê)

Um roteiro por vez, contra o inventário. Ordem do mais grave ao menos:

| # | Roteiro | Pergunta |
|---|---|---|
| 1 | [acesso-cruzado](../explore/hunts/acesso-cruzado.md) | um usuário alcança o que é de outro, ou vira o que não é? |
| 2 | [injecao-e-ssrf](../explore/hunts/injecao-e-ssrf.md) | dado de fora vira comando, HTML, caminho ou destino de rede? |
| 3 | [ia-e-agentes](../explore/hunts/ia-e-agentes.md) | quem escreve o que o modelo lê consegue mandar no sistema? |
| 4 | [custo-e-logica](../explore/hunts/custo-e-logica.md) | dá para usar sem pagar, repetir, ou ganhar uma corrida? |
| 5 | [segredos-e-config](../explore/hunts/segredos-e-config.md) | há chave onde não devia, ou porta aberta por configuração? |

## Etapa 4 — Conformidade módulo a módulo

O que a caça não cobriu: rodar o **Checklist** de cada módulo aplicável contra o inventário.

- [ ] [authentication](../core/authentication.md) · [crypto-data-protection](../core/crypto-data-protection.md) · [logging-monitoring](../core/logging-monitoring.md) · [dependencies-supply-chain](../core/dependencies-supply-chain.md) · [frontend-security](../core/frontend-security.md) · [secure-design](../core/secure-design.md)
- [ ] Conferir no [owasp-mapping.md](../owasp-mapping.md) se alguma categoria ficou sem verificação

## Etapa 5 — Fora do repositório

- [ ] Configuração feita no painel da plataforma (Auth, limites, buckets, chaves ativas) e os verificadores dela
- [ ] Histórico do git: secret scan com histórico completo (`secrets-config` P4)
- [ ] Dependências: `npm audit` / OSV
- [ ] O ambiente **publicado**: headers e erros que o servidor de fato devolve

## Etapa 6 — Relatório e registro

- [ ] Cada achado no formato do protocolo (estado, onde, evidência, correção, **teste que prova a correção**)
- [ ] Seção final: o que foi analisado e o que NÃO foi
- [ ] CRÍTICOS corrigidos antes de qualquer outra coisa — e cada correção acompanhada do teste que antes falhava
- [ ] `SECURITY-STATUS.md` do projeto atualizado ([modelo](../templates/SECURITY-STATUS.md)): achados em aberto, exceções, data
- [ ] Rodar a varredura de novo depois das correções

## Prompt pronto (para usar com sua IA)

```text
Explore a segurança deste projeto usando o security-playbook
(<caminho-do-clone>/SECURITY.md), seguindo checklists/audit.md.

1. Rode a varredura: deno task explore <este-projeto> --md relatorio.md
   (a partir do clone do playbook) e leia primeiro a seção de cobertura.
2. Monte o inventário (Etapa 1) lendo o código real.
3. Faça a triagem de cada suspeito e depois a caça pelos roteiros de
   explore/hunts/, um por vez.
4. Siga explore/PROTOCOLO.md: todo achado é "confirmado" (com a prova) ou
   "suspeito" (com o que falta verificar). Nada de "provavelmente".
   Prova de execução só em ambiente local — nunca em produção.
5. Termine dizendo o que foi analisado e o que NÃO foi.

Não corrija nada ainda — primeiro o relatório completo, depois decidimos juntos.
```

> Em projeto grande, uma etapa por sessão (varredura + inventário → triagem → um roteiro de caça por vez → relatório) mantém a qualidade da análise.
