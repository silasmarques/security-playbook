---
owasp: [A07]
last-review: 2026-06-11
sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
  - https://supabase.com/docs/guides/auth
---

# Autenticação

> Quem é o usuário, e como provamos isso a cada request. Consulte ao mexer em login, signup, reset de senha, sessões, JWT ou qualquer fluxo de credencial.

## Regras

- **R1 — MUST** delegar autenticação a um provedor estabelecido (Supabase Auth, OAuth de provedor conhecido). **NEVER** implementar armazenamento de senha próprio. Se for absolutamente inevitável: argon2id (preferido) ou bcrypt com cost ≥ 12 — nunca MD5/SHA-1/SHA-256 puro, com ou sem salt.
- **R2 — MUST** validar o token no servidor a cada request que decide algo: assinatura verificada, `exp` respeitado, `aud`/`iss` conferidos. **NEVER** apenas decodificar o JWT e confiar no payload.
- **R3 — MUST** usar `supabase.auth.getUser()` (valida o token contra o servidor) quando a decisão é de segurança. `getSession()` lê do storage local sem validar — serve para UX, não para autorização.
- **R4 — MUST** aplicar rate limiting nos fluxos de credencial: login, signup, reset de senha, verificação de e-mail. São os endpoints mais atacados por força bruta e enumeração.
- **R5 — MUST** retornar erros genéricos nos fluxos de credencial ("credenciais inválidas"). **NEVER** revelar se o e-mail existe ("usuário não encontrado" ≠ "senha errada" é enumeração de contas).
- **R6 — MUST** tokens de reset/convite/verificação: single-use, expiração curta (≤ 1h), invalidados imediatamente após o uso e após novo pedido.
- **R7 — NEVER** transportar credenciais ou tokens de sessão em URL (query string vaza em logs, histórico, Referer). Tokens em header `Authorization` ou cookie seguro.
- **R8 — MUST** revogar/rotacionar sessões em eventos sensíveis: troca de senha, troca de e-mail, elevação de privilégio, suspeita de comprometimento.

## Padrões prontos

### P1 — Verificação de usuário em Edge Function (server-side)

```typescript
import { createClient } from "jsr:@supabase/supabase-js@2";

Deno.serve(async (req) => {
  // Client com o token DO CHAMADOR — getUser valida no servidor de auth.
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: req.headers.get("Authorization")! } } },
  );

  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) {
    return new Response(JSON.stringify({ error: "Autenticação necessária" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
  // user.id é confiável daqui pra frente — veio do token verificado,
  // nunca do body/query. Próximo passo: autorização (core/authorization.md).
});
```

### P2 — Erro genérico no login (frontend)

```typescript
// Uma única mensagem para QUALQUER falha de credencial.
const GENERIC_LOGIN_ERROR = "E-mail ou senha inválidos.";

async function handleLogin(email: string, password: string) {
  const { error } = await supabase.auth.signInWithPassword({ email, password });
  if (error) {
    // Não inspecionar error.message para diferenciar "não existe" de "senha errada".
    // O detalhe real fica no log do provedor, não na UI.
    setError(GENERIC_LOGIN_ERROR);
    return;
  }
  // sucesso...
}
```

### P3 — Política de senha (alinhada a NIST/OWASP)

```text
- Mínimo 8 caracteres (recomendado aceitar até 64+; frases longas > regras de composição)
- SEM regras arbitrárias de composição ("1 maiúscula, 1 símbolo...") — geram senhas piores
- SEM expiração periódica forçada — só trocar em suspeita de comprometimento
- Checar contra senhas vazadas quando o provedor suportar
  (Supabase: Auth > Settings > "Leaked password protection")
- MFA habilitado para contas administrativas, oferecido para todas
```

## Anti-padrões

```typescript
// ❌ NUNCA: decodificar JWT e confiar no payload [viola R2]
import { jwtDecode } from "jwt-decode";
const payload = jwtDecode(token);
if (payload.role === "admin") grantAccess(); // payload é forjável sem a assinatura

// ❌ NUNCA: decidir segurança com getSession() [viola R3]
const { data: { session } } = await supabase.auth.getSession();
if (session) deleteResource(id); // session vem do localStorage, não foi validada

// ❌ NUNCA: identidade vinda do request [viola R2]
const userId = body.userId; // qualquer um manda qualquer userId
await db.from("documents").select().eq("user_id", userId);

// ❌ NUNCA: erro que enumera contas [viola R5]
if (!userExists) return res.status(404).send("Usuário não encontrado");
```

## Checklist

- [ ] Endpoints novos validam o token no servidor (`getUser()`, não `getSession()`)?
- [ ] Identidade sempre extraída do token verificado, nunca de body/query?
- [ ] Erros de credencial são genéricos (sem enumeração de contas)?
- [ ] Nenhum token/credencial em URL ou em log?
- [ ] Fluxos de credencial têm rate limiting?
- [ ] Tokens de reset/convite são single-use com expiração curta?
- [ ] Mudança de senha/privilégio revoga sessões existentes?
