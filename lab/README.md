# Laboratório — a cobaia

> [cobaia/](cobaia/) é um app pequeno e **vulnerável de propósito**: notas com resumo por IA, sobre React + Supabase. Existe para responder, com número, a pergunta "o explorador encontra o que deveria?". **Não use nada daqui como exemplo de código.**

## O que tem plantado

[gabarito.json](gabarito.json) lista **52 falhas** e as iscas:

| Tipo | Quantas | Quem deve achar |
|---|---|---|
| Falhas de padrão (banco, código, config) | 45 | a varredura — `deno task explore lab/cobaia` |
| Falhas de lógica (IDOR em função, IA sem cap, prompt injection, BYOK em claro, webhook sem assinatura, corrida de créditos, enumeração de contas) | 7 | a caça com roteiro — `eval/run-audit.ts` |
| Iscas — construções corretas que **não** podem ser acusadas | 12 | ninguém |

## Como ler os números

- **Varredura: 45 de 45, zero iscas acusadas.** É teste de **regressão**, não medida independente de qualidade: as regras e o gabarito foram escritos juntos. Garante que uma mudança futura não quebre uma regra em silêncio. A medida independente veio de rodar em projetos reais — ver "Limites" em [../explore/README.md](../explore/README.md).
- **Caça com IA: medida à parte, fora do CI** (custa tokens e varia a cada execução). `deno run -A eval/run-audit.ts` copia a cobaia **sem o gabarito**, pede a auditoria pelo roteiro e compara os achados com as 52 falhas: recall, e quantos achados ficaram fora do gabarito (falso positivo, ou falha real que ninguém plantou — exige leitura).

## Regra do laboratório

Falha nova que o explorador deva achar entra **primeiro** aqui — plantada na cobaia e registrada no gabarito — e só depois vira regra. Regra sem falha plantada correspondente não tem como falhar, e o que não pode falhar não prova nada.

O "segredo" em `cobaia/supabase/functions/save-settings/index.ts` é um JWT falso, sem valor em serviço algum; o scanner de segredos deste repositório ignora a pasta `lab/` por configuração ([.gitleaks.toml](../.gitleaks.toml)).
