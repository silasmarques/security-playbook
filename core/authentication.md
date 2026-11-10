---
owasp: [A07]
last-review: 2026-11-10
sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
  - https://supabase.com/docs/guides/auth
  - https://supabase.com/docs/guides/auth/rate-limits
  - https://pages.nist.gov/800-63-4/sp800-63b.html
  - https://supabase.com/docs/reference/javascript/auth-getclaims
---

# Autenticação

> Quem é o usuário, e como provamos isso a cada request. Consulte ao mexer em login, signup, reset de senha, sessões, JWT ou qualquer fluxo de credencial.

## Regras

- **R1 — MUST** delegar autenticação a um provedor estabelecido (Supabase Auth, OAuth de provedor conhecido). **NEVER** implementar armazenamento de senha próprio. Se for absolutamente inevitável: argon2id (preferido) ou bcrypt com cost ≥ 12 — nunca MD5/SHA-1/SHA-256 puro, com ou sem salt.
- **R2 — MUST** validar o token no servidor a cada request que decide algo: assinatura verificada, `exp` respeitado, `aud`/`iss` conferidos. **NEVER** apenas decodificar o JWT e confiar no payload.
- **R3 — MUST** a identidade usada numa decisão de segurança vem de token **validado pelo servidor** naquela requisição — nunca de sessão lida do armazenamento local nem de payload decodificado. Na stack Supabase: `getUser()` (consulta o Auth) ou `getClaims()` (verifica a assinatura; recomendado pela doc quando o projeto usa chave assimétrica). `getSession()` serve para UX, não para autorização.
- **R4 — MUST** aplicar rate limiting nos fluxos de credencial: login, signup, reset de senha, verificação de e-mail. São os endpoints mais atacados por força bruta e enumeração. Atenção: o padrão por usuário (`api-security.md` P2) exige `user_id` — não cobre pré-login; a defesa pré-auth é o P4 (limites nativos do provedor + IP na borda).
- **R5 — MUST** retornar erros genéricos nos fluxos de credencial ("credenciais inválidas"). **NEVER** revelar se o e-mail existe ("usuário não encontrado" ≠ "senha errada" é enumeração de contas).
- **R6 — MUST** tokens de reset/convite/verificação: single-use, expiração curta (≤ 1h), invalidados imediatamente após o uso e após novo pedido.
- **R7 — NEVER** transportar credenciais ou tokens de sessão em URL (query string vaza em logs, histórico, Referer). Tokens em header `Authorization` ou cookie seguro.
- **R8 — MUST** revogar/rotacionar sessões em eventos sensíveis: troca de senha, troca de e-mail, elevação de privilégio, suspeita de comprometimento.
- **R9 — MUST** login social/OAuth: `state` imprevisível e conferido na volta (anti-CSRF do fluxo), PKCE em cliente público (SPA, mobile), e `redirect_uri` por allowlist exata no provedor — nunca curinga. Conta só é vinculada a e-mail **verificado** pelo provedor.
- **R10 — MUST** ação de alto impacto (trocar e-mail/senha, apagar conta, gerar chave de API, mudar pagamento) pede reautenticação recente ou segundo fator — sessão antiga sozinha não basta.

## Padrões prontos

### P1 — Verificação de usuário no servidor

O passo 3 do template completo em [kit/supabase/function-template/index.ts](../kit/supabase/function-template/index.ts):

<!-- ilustrativo -->

```typescript
import { createClient } from "jsr:@supabase/supabase-js@2";

Deno.serve(async (req) => {
  // Client com o token DO CHAMADOR — getUser valida no servidor de auth.
  const authorization = req.headers.get("Authorization");
  if (!authorization?.startsWith("Bearer ")) {
    return new Response(JSON.stringify({ error: "Autenticação necessária" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }
  const supabase = createClient(
    Deno.env.get("SUPABASE_URL")!,
    Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: authorization } } },
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
  return new Response(JSON.stringify({ ok: true }), {
    headers: { "Content-Type": "application/json" },
  });
});
```

### P2 — Erro genérico no login (frontend)

<!-- ilustrativo -->

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

### P3 — Política de senha (NIST SP 800-63B-4)

```text
- Senha como ÚNICO fator: mínimo 15 caracteres. Com MFA obrigatório: mínimo 8.
- Aceitar pelo menos 64 caracteres, qualquer caractere (espaço e Unicode inclusive)
- SEM regras de composição ("1 maiúscula, 1 símbolo...") — a norma as proíbe: geram senhas piores
- SEM expiração periódica forçada — só trocar em suspeita de comprometimento
- Checar contra senhas vazadas quando o provedor suportar
  (Supabase: Auth > Settings > "Leaked password protection")
- MFA habilitado para contas administrativas, oferecido para todas
- Quando o provedor suportar, preferir MFA resistente a phishing (passkeys/WebAuthn):
  TOTP protege contra reuso de senha, não contra phishing em tempo real
```

### P4 — Rate limit pré-autenticação (limites nativos + borda)

Antes do login não existe `user_id`, então o rate limit por usuário não alcança. A defesa vem em duas camadas:

**1. Limites nativos do provedor.** Na Supabase (valores conferidos na doc em 2026-07-02 — reconferir no painel do projeto, eles mudam; configurar em Dashboard → Authentication → Rate Limits):

| Endpoint | Default | Configurável? |
|---|---|---|
| E-mails (signup/reset, provedor built-in) | 2/hora | só com SMTP próprio |
| OTP | 30/hora (projeto) | sim |
| Verificação | 360/hora por IP | não |
| Token refresh | 1800/hora por IP | não |
| MFA | 15/hora por IP | não |

> O provedor de e-mail built-in (2/h) é para desenvolvimento — produção configura
> SMTP próprio e ajusta os limites de e-mail conscientemente.

**2. Endpoints próprios pré-auth** (formulário público, contato, webhook de entrada): limite por IP na borda — WAF/firewall do host (Vercel, Cloudflare) — porque o contador em Postgres por usuário (`api-security.md` P2) não enxerga quem não tem conta.

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
- [ ] Fluxos de credencial têm rate limiting — nativos do provedor revisados + borda por IP nos endpoints próprios (P4)?
- [ ] Tokens de reset/convite são single-use com expiração curta?
- [ ] Mudança de senha/privilégio revoga sessões existentes?
- [ ] OAuth com `state` conferido, PKCE e `redirect_uri` exata; vínculo só com e-mail verificado?
- [ ] Ações de alto impacto exigem reautenticação recente ou segundo fator?
