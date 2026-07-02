---
owasp: [A05, A06]
last-review: 2026-06-11
sources:
  - https://www.typescriptlang.org/tsconfig/
  - https://vite.dev/guide/env-and-mode
  - https://react.dev/reference/react-dom/components/common#dangerously-setting-the-inner-html
---

# React + TypeScript (Vite)

> TypeScript estrito é ferramenta de segurança: a maioria dos bugs exploráveis de frontend começa com um tipo que mentiu. XSS e DOM estão em `../core/frontend-security.md` — este módulo cobre o que é específico de React/TS/Vite.

## Regras

- **R1 — MUST** `"strict": true` no tsconfig de TODO projeto novo (+ `noUncheckedIndexedAccess` recomendado). Projeto existente não-estrito: plano de migração incremental registrado (lacuna recorrente em projetos reais auditados).
- **R2 — NEVER** `any` em fronteiras: resposta de API, `JSON.parse`, props públicas de lib, `import.meta.env`. O padrão é `unknown` + schema zod para estreitar (P2).
- **R3 — MUST** `npx tsc --noEmit` com zero erros antes de qualquer push (norma do fluxo de trabalho, já obrigatória — aqui ganha justificativa de segurança).
- **R4 — MUST** XSS: seguir `../core/frontend-security.md` (wrapper `SafeHtml`, `safeHref`). Este módulo não duplica — referencia.
- **R5 — MUST** validar `import.meta.env` na inicialização com schema (P3) e falhar rápido se faltar variável — app que sobe com env errada falha de formas criativas e silenciosas.
- **R6 — MUST** guarda de rota única (`<RequireAuth>`) envolvendo as rotas autenticadas — nunca checagem copiada página a página. E lembrar: guard de UI é UX; a segurança real é RLS + validação no servidor.
- **R7 — MUST** redirect pós-login por allowlist de path interno (P4). **NEVER** `navigate(searchParams.get("next"))` cru — open redirect serve phishing com o SEU domínio.
- **R8 — MUST** estado sensível digitado pelo usuário (chave BYOK, senha de integração): enviar direto ao servidor para criptografia; **NEVER** persistir em localStorage/sessionStorage em claro nem manter em estado global além do necessário.

## Padrões prontos

### P1 — tsconfig estrito de referência

```jsonc
{
  "compilerOptions": {
    "strict": true,                       // o pacote todo: strictNullChecks, noImplicitAny...
    "noUncheckedIndexedAccess": true,     // arr[i] é T | undefined — força a checagem
    "noImplicitOverride": true,
    "exactOptionalPropertyTypes": true,
    "verbatimModuleSyntax": true,
    "skipLibCheck": true
  }
}
```

### P2 — Fronteira de API tipada de verdade

```typescript
import { z } from "zod";

const artifactSchema = z.object({
  id: z.string().uuid(),
  title: z.string(),
  kind: z.enum(["bdd", "test-plan", "checklist"]),
});

export async function fetchArtifact(id: string) {
  const res = await fetch(`/api/artifacts/${id}`);
  if (!res.ok) throw new Error(`falha ao buscar artifact: ${res.status}`);
  const data: unknown = await res.json();     // unknown, não any nem cast
  return artifactSchema.parse(data);          // tipo provado em runtime
}
```

### P3 — Validação de env na inicialização

```typescript
// src/env.ts — importado no main.tsx antes de tudo
import { z } from "zod";

const envSchema = z.object({
  VITE_SUPABASE_URL: z.string().url(),
  VITE_SUPABASE_ANON_KEY: z.string().min(1),
  // Se você se pegar adicionando VITE_*_SECRET aqui, pare: VITE_ = público.
});

export const env = envSchema.parse(import.meta.env); // falha no boot, não no clique
```

### P4 — Guard de rota + redirect allowlistado

```tsx
export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { session, loading } = useAuth();
  const location = useLocation();
  if (loading) return <Spinner />;
  if (!session) {
    return <Navigate to="/login" state={{ next: location.pathname }} replace />;
  }
  return <>{children}</>;
}

// Pós-login: só paths internos passam
function safeNext(next: unknown): string {
  return typeof next === "string" && next.startsWith("/") && !next.startsWith("//")
    ? next
    : "/";
}
const { state } = useLocation();
navigate(safeNext(state?.next));
```

## Anti-padrões

```typescript
// ❌ NUNCA: cast para calar o compilador na fronteira [viola R2]
const user = (await res.json()) as User;  // o servidor mudou? você descobre em prod

// ❌ NUNCA: redirect cru de query string [viola R7]
navigate(searchParams.get("redirect")!);
// ?redirect=https://evil.com/login → phishing hospedado na SUA URL

// ❌ NUNCA: chave do usuário no localStorage [viola R8]
localStorage.setItem("gemini_key", userApiKey); // qualquer XSS futura lê tudo

// ❌ NUNCA: checagem de auth copiada em cada página [viola R6]
useEffect(() => { if (!session) navigate("/login"); }, []); // em 14 páginas, 13 atualizadas
```

## Checklist

- [ ] tsconfig estrito (ou migração registrada em projeto legado)?
- [ ] `npx tsc --noEmit` zero erros?
- [ ] Fronteiras com `unknown` + schema, sem `as` de conveniência?
- [ ] Env validada no boot, sem `VITE_` contendo secret?
- [ ] Rotas autenticadas sob `<RequireAuth>` único?
- [ ] Redirects dinâmicos allowlistados?
- [ ] Nenhum dado sensível em localStorage/estado além do necessário?
