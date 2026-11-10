# Caça: injeção e SSRF

> A pergunta: **um dado que vem de fora consegue virar comando — SQL, HTML/script, caminho de arquivo, destino de rede ou de redirect?** Norma: [input-validation](../../core/input-validation.md), [frontend-security](../../core/frontend-security.md), [authorization](../../core/authorization.md) R6. Seguir o [protocolo de evidência](../PROTOCOLO.md).

## Inventário primeiro

Liste todas as **fontes** (body, query, header, cookie, arquivo enviado, webhook, conteúdo de terceiros, resposta de IA) e todos os **destinos perigosos** (query de banco, HTML renderizado, chamada de rede, sistema de arquivos/storage, redirect, comando). A caça é ligar fonte a destino sem controle no meio.

## Hipóteses

### H1 — SQL montado com texto do usuário
- **Procurar:** string de SQL com interpolação; `EXECUTE` com concatenação dentro de função do banco. Regras `C-SQL-CONCAT`, `C-SQL-DYNAMIC-EXEC`.
- **Provar:** rastro do valor até a query; em ambiente local, enviar `'` e observar erro de sintaxe do banco, ou uma condição sempre verdadeira mudando o resultado.
- **Falso positivo:** o valor interpolado é constante do código, ou passou por schema que só aceita formato fechado (UUID, enum).

### H2 — Conteúdo externo renderizado como HTML
- **Procurar:** inserção de HTML dinâmico, markdown com HTML habilitado, `href`/`src` vindos de dado. Regras `C-DANGEROUS-HTML`, `C-REHYPE-RAW`. Atenção especial ao que vem de **IA**: a origem real é o documento que o modelo leu.
- **Provar:** gravar `<img src=x onerror=alert(1)>` no campo e abrir a tela onde ele aparece.
- **Falso positivo:** passa por sanitizador com allowlist antes de chegar ao DOM; ou o conteúdo é 100% gerado pelo próprio código.

### H3 — O servidor busca a URL que o usuário manda (SSRF)
- **Procurar:** chamada de rede cujo destino vem de fora ou de resposta de IA. Regra `C-FETCH-DYNAMIC-URL`. Olhar também o que segue redirect automaticamente.
- **Provar:** em ambiente local, apontar para um servidor seu que registra a visita; depois para `http://127.0.0.1:<porta>/` e para um endereço que **redireciona** para lá. Confirmado se o servidor alcança o destino interno.
- **Falso positivo:** o host é fixo e só o caminho varia; ou a chamada passa por validador que classifica o IP em todas as formas **e** revalida cada redirect (confira os dois — validar só a primeira URL é o erro mais comum).

### H4 — Nome ou tipo de arquivo decidido pelo cliente
- **Procurar:** upload que grava com o nome enviado; que confia em extensão ou content-type; que aceita SVG/HTML.
- **Provar:** enviar `../../x`, um executável renomeado e um SVG com script; ver onde foi gravado e como é servido.

### H5 — Redirect para onde a URL mandar
- **Procurar:** destino de navegação lido de parâmetro. Regra `C-OPEN-REDIRECT`.
- **Provar:** `?next=//exemplo.org`, `?next=/\exemplo.org`. Confirmado se o navegador sai do site.

### H6 — Campo a mais aceito em silêncio (mass assignment)
- **Procurar:** body repassado inteiro para insert/update; schema que não rejeita campo desconhecido.
- **Provar:** acrescentar `role`, `user_id`, `price` ao payload e ver se foram gravados.

## Correção

Schema estrito na fronteira ([schema.ts](../../kit/supabase/function-template/schema.ts)) · query parametrizada · renderizar como texto, ou wrapper sanitizado único · `safeFetch` ([ssrf.ts](../../kit/web/ssrf.ts)) · upload validado pelo conteúdo ([upload.ts](../../kit/web/upload.ts)) · `safeNext` ([safe-url.ts](../../kit/web/safe-url.ts)).
