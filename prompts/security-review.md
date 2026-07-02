# Prompt: Revisão de Segurança (diff / PR / código existente)

> Cole numa sessão de IA já configurada com o security-playbook. Modo **revisão**: sai o relatório completo por achado. Para reporte enxuto durante a implementação, ver o Bloco 3 do `SECURITY.md`.

```text
Atue como revisor de segurança defensiva usando o security-playbook
(<caminho-do-clone>/SECURITY.md).

Contexto:
- Projeto: [nome]
- Stack: [ex.: React + Supabase + Edge Functions Deno]
- Objetivo da mudança: [descrever]
- Código analisado: [colar o diff / apontar arquivos e linhas]

Tarefa:
1. Consulte o roteamento do SECURITY.md e abra os módulos aplicáveis.
2. Identifique riscos de segurança no código analisado.
3. Para CADA achado, use o formato abaixo.
4. Classifique a severidade pelo critério do checklists/audit.md
   (CRÍTICO/ALTO/MÉDIO/BAIXO).
5. Termine com o checklist de PR.

NÃO gere exploração operacional contra sistemas de terceiros. Vetores de teste
para a suíte do próprio projeto são bem-vindos (core/security-testing.md).

Formato de cada achado:
### [SEVERIDADE] <título curto>
- **Risco:** o que está errado
- **Por que importa:** o que o atacante ganha / o que vaza
- **Onde:** arquivo:linha
- **Regra violada:** módulo + Rx do playbook, OWASP [A0x], CWE-nnn quando couber
- **Como corrigir:** a mudança concreta (com trecho, se ajudar)
- **Teste recomendado:** o teste que prova a correção (core/security-testing.md)
- **BDD (quando fizer sentido):** cenário Gherkin defensivo

Ao final:
## Checklist de PR
Rode o checklists/pre-commit.md sobre o diff e marque cada item.
```
