# Protocolo de Evidência

> Vale para toda exploração — feita pela varredura (`deno task explore`), por uma IA seguindo os roteiros de [hunts/](hunts/) ou por uma pessoa. A regra que organiza tudo: **nenhuma afirmação sem evidência, e toda evidência diz o seu alcance.**

## 1. Só existem três estados para um achado

| Estado | Significa | Exige |
|---|---|---|
| **confirmado** | A falha foi observada acontecendo, ou é fato objetivo do artefato | Uma prova da seção 2 |
| **suspeito** | O padrão costuma ser falha, mas falta ver o contexto | Dizer o que falta verificar e como |
| **descartado** | Foi verificado e não é falha | O motivo, em uma linha |

Não existe "provavelmente vulnerável". Sem prova, é **suspeito** — e o relatório diz isso. Rebaixar um suspeito para descartado também exige verificação: "parece ok" não é motivo.

## 2. O que conta como prova

Em ordem de força. Use a mais forte que o ambiente permitir.

1. **Execução que mostra o efeito.** Um teste ou comando em que o acesso indevido *acontece*: usuário B lê a linha de A; a chamada 31 passa quando o limite é 30; o servidor busca `http://169.254.169.254/`. Para banco, a bancada [supabase/probe.ts](supabase/probe.ts) sobe as migrations do projeto num Postgres real e executa SQL como anônimo, como usuário e como servidor.
2. **Estado do artefato.** O catálogo do banco depois das migrations (`relrowsecurity = false`), o arquivo de configuração publicado, o header que o servidor de fato devolve.
3. **Rastro no código, de ponta a ponta.** O caminho completo, com `arquivo:linha` em cada passo, de onde o dado entra (fonte) até onde causa dano (destino), **sem** controle no meio. Ler só o destino não é prova: o controle pode estar três chamadas acima.

Não é prova: nome de função ("`validateUrl` deve validar"), comentário, documentação, o que "normalmente" acontece naquele framework, nem teste que reimplementa a regra em vez de exercitar o sistema.

## 3. Antes de escrever "confirmado" — o teste de mesa

- **Se o sistema estivesse correto, esta prova daria outro resultado?** Se daria o mesmo, ela não prova nada.
- **Há controle positivo?** "B não vê" só vale junto de "A vê".
- **A prova rodou no alvo real ou num substituto?** Dizer qual. Banco reconstruído das migrations não é o banco de produção: mudança feita no painel não aparece.

## 4. Limites que não se cruzam

- Só o **sistema próprio ou autorizado**. Nunca testar contra terceiros.
- Prova de execução roda em **ambiente local ou de staging** — nunca em produção, nunca com dado real de usuário.
- A prova demonstra o efeito mínimo (ler uma linha de teste), não o dano máximo. Nada de extrair dados, apagar ou persistir acesso.
- Segredo encontrado **não é copiado** para o relatório: indica-se o lugar e os primeiros caracteres.

## 5. Formato do achado

```text
### [SEVERIDADE] <título curto>
- Estado: confirmado | suspeito
- Onde: arquivo:linha (ou objeto de banco)
- Evidência: o que foi visto/executado, literalmente — e em que ambiente
- Por que importa: o que o atacante ganha
- Como corrigir: a mudança concreta + o padrão da norma (módulo Rx / arquivo do kit)
- Como provar a correção: o teste que hoje falha e depois passa
- (se suspeito) Falta verificar: o quê, e como
```

Severidade: **CRÍTICO** = exploração direta expõe ou altera dado/dinheiro de outros · **ALTO** = exploração viável com algum esforço ou pré-condição · **MÉDIO** = falta uma camada de defesa · **BAIXO** = higiene.

Para consumo por máquina (e pela avaliação em `eval/run-audit.ts`), o mesmo conteúdo em `achados.json`:

```json
[{ "titulo": "…", "severidade": "CRÍTICO", "estado": "confirmado", "classe": "acesso",
   "arquivo": "supabase/functions/x/index.ts", "linha": 14, "evidencia": "…", "correcao": "…" }]
```

`classe` é uma de: `acesso` · `injecao` · `segredos` · `custo` · `logica` · `cripto` · `resiliencia` · `config`.

## 6. Todo relatório termina dizendo o que NÃO foi visto

Obrigatório, mesmo quando nada foi encontrado:

- o que foi analisado (pastas, migrations aplicadas, funções lidas);
- o que **não** foi, e por quê (migration que não aplicou, pasta ignorada, classe de falha fora do roteiro, ambiente indisponível para prova);
- o que só outro meio alcança (painel da plataforma, histórico do git, pentest).

"Não encontrei nada" sem essa seção é uma afirmação sem alcance — e é lida como "está seguro", que ninguém verificou.
