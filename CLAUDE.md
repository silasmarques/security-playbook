# security-playbook — instruções para trabalhar NESTE repositório

Norma de segurança + kit de código testado + explorador de falhas. Público, em pt-BR. Visão geral: [README.md](README.md).

## Princípio que rege qualquer mudança

**Nada entra na norma sem um teste que falha quando o padrão está quebrado.** Afirmação técnica nova exige evidência: teste que roda, ou fonte oficial com a data da consulta. "Deve funcionar" não entra.

## Comandos

```bash
deno task ci         # tudo o que o CI roda — obrigatório antes de commit
deno task test       # testes (kit, SQL em Postgres real via PGlite, explorador, suítes)
deno task docs       # links, referências Rn/Pn, matriz OWASP, contagens
deno task snippets   # norma idêntica ao kit? (snippets:write reescreve os .md)
deno task mutation   # quebra 43 controles de propósito; a suíte tem de perceber
deno task explore <projeto>
```

## Onde mexer

| Para mudar… | Edite | Depois |
|---|---|---|
| um "Padrão pronto" | o arquivo em `kit/` + o teste em `kit/tests/` | `deno task snippets:write` — nunca edite o bloco no `.md` |
| uma regra da norma | o módulo em `core/` ou `stack/` | atualizar `last-review`; se mudou tag OWASP, a matriz |
| uma regra do explorador | **primeiro** plantar a falha em `lab/cobaia/` e registrar em `lab/gabarito.json`; depois `explore/` | caso que dispara e caso que se cala em `explore/scan.test.ts` |
| uma garantia anunciada | o teste | acrescentar a mutação em `scripts/mutation-check.ts` |

## Regras da casa

- **Duas camadas, sem misturar:** `core/`, `kit/web/` e `explore/code-checks.ts` são universais (nenhuma dependência de plataforma); o que é Supabase/Postgres fica em `stack/`, `kit/supabase/`, `explore/supabase/`.
- Bloco TS/SQL em "Padrões prontos" tem marcador `<!-- kit: caminho#regiao -->` ou `<!-- ilustrativo -->`. O CI recusa o que não tiver.
- Número anunciado no README (testes, mutações, falhas da cobaia) tem de bater com a saída real dos comandos — conferir antes de commitar.
- `lab/cobaia/` é vulnerável de propósito e não leva comentário que entregue a falha: ela é usada para avaliar agentes às cegas.
- Limites e o que não foi verificado são parte do produto: ao acrescentar capacidade, atualizar a seção "Limites" correspondente.
- `docs/` é gitignored (specs e planos internos) — não é versionado; não guardar lá nada que não possa se perder.
- As suítes `eval/run-*.ts` chamam o CLI `claude`, custam tokens e não rodam no CI. Só executar a pedido.
