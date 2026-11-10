---
owasp: [A06]
last-review: 2026-11-10
sources:
  - https://owasp.org/Top10/2025/
  - https://cheatsheetseries.owasp.org/cheatsheets/Threat_Modeling_Cheat_Sheet.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Secure_Product_Design_Cheat_Sheet.html
  - https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm
---

# Desenho Seguro (arquitetura)

> Os outros módulos dizem como escrever cada peça. Este diz como decidir o desenho antes de escrever — onde ficam as fronteiras, quem confia em quem, o que acontece quando uma peça falha. Falha de desenho não se conserta com um `if`: um sistema que guarda a chave de serviço no cliente não fica seguro por validar input. Vale para qualquer stack.

## Regras

- **R1 — MUST** modelar ameaças ANTES de construir: para cada feature, as 5 perguntas de `../checklists/new-feature.md` respondidas por escrito. O resultado fica no projeto, não na cabeça de quem fez.
- **R2 — MUST** desenhar as **fronteiras de confiança**: onde dado sai de uma zona não confiável e entra numa confiável. Não confiáveis por definição: navegador e app do usuário, conteúdo de terceiros, resposta de LLM, webhook de parceiro, e outro serviço interno até prova em contrário. Em cada travessia há validação e autorização — do lado de dentro.
- **R3 — MUST** classificar os dados: **público** · **interno** · **confidencial** (dado de usuário) · **restrito** (credenciais, dado pessoal sensível, financeiro). A classe decide onde o dado pode ficar, quem lê, se é cifrado e se pode aparecer em log (P2). Dado sem classe é tratado como restrito.
- **R4 — MUST** decidir o **modelo de isolamento** no dia 1 — por usuário, por organização, ou os dois — e impô-lo na camada de dados (RLS, filtro obrigatório no repositório), não só no código da tela. Trocar de modelo depois é reescrever todas as queries.
- **R5 — MUST** menor privilégio por componente: cada peça recebe só a credencial de que precisa. A credencial mais poderosa existe no menor número possível de lugares, e nunca num lugar que o usuário controla.
- **R6 — MUST** defesa em profundidade para o que é crítico: pelo menos **dois controles independentes** entre o atacante e o ativo (ex.: filtro de dono no código **e** RLS; RLS **e** privilégio revogado). Um controle só é um ponto único de falha.
- **R7 — MUST** padrão seguro: a configuração que sai da caixa nega. Abrir é ação explícita, registrada e reversível; ninguém precisa lembrar de fechar.
- **R8 — MUST** ciclo de vida do dado pessoal: coletar o mínimo para a finalidade, prazo de retenção definido, caminho de exclusão que funciona (apagar a conta apaga ou anonimiza o que é dela — inclusive arquivos e embeddings) e saber exportar o que se tem de uma pessoa. No Brasil isso é obrigação da LGPD; a base legal de cada tratamento fica registrada. *(Este módulo não substitui orientação jurídica.)*
- **R9 — MUST** recuperação planejada: backup dos dados com **restauração testada**, e conhecimento de quanto se perde (RPO) e em quanto tempo se volta (RTO). Para segredo que não se rotaciona, `secrets-config.md` R9.
- **R10 — MUST** estar pronto para o incidente antes dele: um roteiro de uma página (P3) dizendo como revogar cada chave, como tirar o sistema do ar, que logs preservar e quem avisar.
- **R11 — MUST** decisão de segurança e exceção à norma ficam registradas no projeto, com o motivo e a data (`../templates/SECURITY-STATUS.md`). Exceção sem registro é dívida que ninguém sabe que existe.

## Padrões prontos

### P1 — Modelo de ameaças de uma feature (preencher antes de codar)

```text
Feature: ______________________________   Data: __________

1. ATIVOS — o que tem valor aqui?
   Dado / recurso            Classe (R3)     Pior caso se vazar ou for alterado
   ________________________  ______________  __________________________________

2. ATORES — quem toca, e quem NÃO pode?
   Visitante sem login · Usuário comum · Usuário de outra organização ·
   Administrador · Serviço interno · Parceiro externo (webhook) · Modelo de IA

3. FRONTEIRAS — por onde o dado entra e sai? (R2)
   Entrada                  Vem de (confiável?)   Onde é validada / autorizada
   _______________________  ____________________  ____________________________
   Saída (API, e-mail, IA)  O que leva            O que custa por chamada
   _______________________  ____________________  ____________________________

4. ABUSOS — para cada ator do item 2, o que ele tentaria?
   [ ] Ler ou alterar o que é de outro (trocar um id)
   [ ] Subir de papel (mandar um campo a mais, editar o próprio registro)
   [ ] Usar de graça ou em volume (repetir, paralelizar, automatizar)
   [ ] Fazer o servidor buscar algo por ele (URL, arquivo, prompt)
   [ ] Plantar conteúdo que outro usuário — ou a IA — vai ler
   [ ] Repetir uma operação que deveria acontecer uma vez

5. FALHAS — se cada dependência cair, demorar ou mentir, o que acontece?
   Dependência           Falha fechada? (nega)   O usuário vê o quê
   ____________________  ______________________  __________________

CONTROLES escolhidos (regra da norma + teste que prova cada um):
   __________________________________________________________________
RISCO ACEITO (o que ficou de fora, por quê, quem decidiu):
   __________________________________________________________________
```

### P2 — Classificação de dados e o que cada classe exige

| Classe | Exemplos | Onde pode ficar | Em log | Em prompt de IA | Cifrado em repouso |
|---|---|---|---|---|---|
| Público | texto de marketing, preço | qualquer lugar | sim | sim | não precisa |
| Interno | métrica agregada, id técnico | servidor, banco | sim | sim | não precisa |
| Confidencial | conteúdo do usuário, e-mail, nome | banco com isolamento por dono | só o id, nunca o conteúdo | só o do próprio usuário, delimitado como dado | disco da plataforma |
| Restrito | senha, token, chave de API, documento pessoal, dado financeiro ou de saúde | secret manager / coluna cifrada | **nunca** | **nunca** | **sim, na aplicação** (`crypto-data-protection.md` P1) |

### P3 — Roteiro de incidente (uma página, escrita ANTES)

```text
1. CONTER (minutos)
   [ ] Chave vazada → revogar/rotacionar: onde (painel, comando) para CADA chave do inventário
   [ ] Conta comprometida → encerrar sessões do usuário; bloquear acesso
   [ ] Falha explorável no ar → como desligar a rota/feature (flag, deploy anterior)
2. PRESERVAR
   [ ] Exportar logs do período antes que a retenção da plataforma apague
   [ ] Anotar a linha do tempo: o que se viu, quando, quem fez o quê
3. ENTENDER
   [ ] O que foi acessado? De quem? Desde quando? (trilha de auditoria + logs)
   [ ] A causa raiz está fechada — ou só o sintoma?
4. AVISAR
   [ ] Usuários afetados e, havendo dado pessoal com risco relevante, a autoridade
       de proteção de dados — prazo e forma definidos pela lei aplicável
5. APRENDER
   [ ] A falha vira regra, teste e item de checklist. Incidente que não muda a norma se repete.
```

### P4 — Mapa de fronteiras (exemplo de uma aplicação web com IA)

```text
 NÃO CONFIÁVEL                 │ FRONTEIRA                  │ CONFIÁVEL
───────────────────────────────┼────────────────────────────┼──────────────────────────
 Navegador / app do usuário    │ API: autentica, autoriza,  │ Lógica de negócio
   (tudo que ele envia)        │ limita, valida             │
 Arquivo enviado               │ tamanho, tipo, conteúdo    │ Storage privado
 URL informada                 │ validação SSRF             │ fetch do servidor
 Documento / página / ticket   │ delimitado como DADO       │ prompt do modelo
 Resposta do modelo de IA      │ schema + sanitização       │ banco, tela, tools
 Webhook de parceiro           │ assinatura + janela        │ processamento do evento
 Chamada entre serviços        │ credencial própria, escopo │ serviço de destino
───────────────────────────────┴────────────────────────────┴──────────────────────────
 Banco de dados: a ÚLTIMA fronteira. Isolamento por dono imposto nele vale mesmo
 quando uma das linhas acima falhar (R6).
```

## Anti-padrões

```text
❌ NUNCA: segurança como fase final [viola R1]
"Primeiro faz funcionar, depois a gente protege." O desenho já decidiu onde a chave
mora e quem fala com o banco — "depois" é reescrever.

❌ NUNCA: confiar na rede interna [viola R2]
"Esse endpoint só é chamado pelo nosso serviço." Até o dia do SSRF, do deploy errado
ou do serviço vizinho comprometido. Chamada interna também se autentica.

❌ NUNCA: um controle só entre o atacante e o dado [viola R6]
Isolamento apenas no filtro do frontend, ou apenas num `if` do handler: a primeira
rota nova que esquecer o `if` expõe tudo.

❌ NUNCA: a chave mais poderosa no lugar mais exposto [viola R5]
Chave de serviço no app mobile, no bundle web ou no repositório "privado".

❌ NUNCA: guardar para sempre "porque pode ser útil" [viola R8]
Dado que não existe não vaza. Cada coluna pessoal a mais aumenta o tamanho do incidente.

❌ NUNCA: backup que nunca foi restaurado [viola R9]
Backup é hipótese até a restauração ser testada.
```

## Checklist

- [ ] Modelo de ameaças da feature preenchido e guardado no projeto (P1)?
- [ ] Cada entrada de dado tem uma fronteira identificada, com validação do lado de dentro?
- [ ] Os dados novos têm classe definida, e o tratamento bate com a tabela do P2?
- [ ] O isolamento (por usuário/organização) é imposto na camada de dados?
- [ ] Há dois controles independentes protegendo o que é crítico?
- [ ] Nenhuma credencial poderosa em lugar controlado pelo usuário?
- [ ] Dado pessoal: mínimo coletado, retenção definida, exclusão de conta cobre tudo?
- [ ] Backup com restauração testada; roteiro de incidente escrito?
- [ ] Decisões e exceções registradas no `SECURITY-STATUS.md` do projeto?
