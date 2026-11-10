# Prompt: Análise Pré-Implementação (antes de codar a feature)

> Cole numa sessão de IA já configurada com o security-playbook. Modo **desenho seguro**: roda o mini threat model e devolve riscos, critérios de aceite e testes ANTES de existir código. Complementa o checklists/new-feature.md.

```text
Atue como consultor de segurança defensiva usando o security-playbook
(<caminho-do-clone>/SECURITY.md). Vou implementar uma feature; analise ANTES de eu codar.

Entrada:
- Requisito: [descrever]
- História de usuário: [como <papel>, quero <ação>, para <valor>]
- Endpoint(s): [método + rota, se já houver]
- Regra de negócio: [restrições, quem pode o quê]
- Código/rascunho (se houver): [colar]

Tarefa — rode o checklists/new-feature.md (as 5 perguntas de ameaça; para feature que
toca dinheiro, dado sensível ou IA, o modelo completo de core/secure-design.md P1) e devolva:

## Riscos
Por risco: descrição, severidade (CRÍTICO/ALTO/MÉDIO/BAIXO, critério do audit.md),
OWASP [A0x] e CWE-nnn quando couber.

## Critérios de aceite de segurança
Lista objetiva do que a feature DEVE garantir para ser aceita.

## BDD defensivo
Cenários Gherkin de sucesso E de abuso (acesso cruzado, input inválido, estouro de
rate limit) — modelo em core/security-testing.md P4.

## Checklist de segurança da feature
Itens verificáveis, derivados dos módulos que o roteamento indicar.

## Sugestão de implementação segura
Como implementar seguindo os padrões prontos dos módulos aplicáveis (citar Px) —
usando os arquivos do kit (kit/README.md), não reescrevendo de memória.
Marque o que é fato conferido no código e o que é hipótese a validar.

## Pontos para code review
Backend / Frontend / Banco: o que o revisor deve conferir em cada camada.

NÃO gere exploração operacional contra terceiros. Vetores de teste para a suíte
do projeto são esperados.
```
