---
owasp: [A09]
last-review: 2026-06-11
sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
  - https://owasp.org/Top10/2025/
---

# Logging e Monitoramento

> O ataque que você não loga é o ataque que você descobre pelo cliente — ou pela fatura. A09 (Security Logging and Alerting Failures) não é sobre logar muito: é sobre logar os eventos certos, sem vazar dados, e ter alguém (ou algo) olhando.

## Regras

- **R1 — MUST** logar eventos de segurança: login falho, acesso negado (403), rate limit atingido, mudança de privilégio/senha, validação rejeitada em sequência, erro 5xx. Com `userId`, `requestId`, timestamp e origem — sem PII além do necessário.
- **R2 — NEVER** logar: secrets, tokens, senhas, chaves de API (inclusive BYOK do usuário), `Authorization` header, corpo completo de request com dado sensível, conteúdo de prompt com dado de cliente.
- **R3 — MUST** logs estruturados (JSON: `level`, `event`, `requestId`, `userId`, `meta`) — agregáveis e pesquisáveis; string solta não vira alerta.
- **R4 — MUST** sanitizar dado externo antes de logar: remover `\n`/`\r` (log injection — atacante forja linhas de log) e truncar tamanho.
- **R5 — MUST** trilha de auditoria persistente (tabela `audit_log`) para operações sensíveis: quem, o quê, em qual recurso, quando. Console some; auditoria fica.
- **R6 — MUST** alerta minimamente viável: 5xx em série, pico de login falho, gasto anômalo de IA por usuário. Um webhook/e-mail simples já muda o jogo — o requisito é alguém ficar sabendo.
- **R7 — MUST** retenção definida: logs de segurança ≥ 90 dias onde a plataforma permitir; saber qual é o limite da plataforma (Supabase/Vercel) e exportar se precisar de mais.

## Padrões prontos

### P1 — Logger estruturado com redação automática

```typescript
const SENSITIVE_KEY = /key|token|secret|password|authorization|cookie/i;

function redact(meta: Record<string, unknown>): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(meta).map(([k, v]) => [
      k,
      SENSITIVE_KEY.test(k) ? "[REDACTED]" : sanitizeLogValue(v),
    ]),
  );
}

function sanitizeLogValue(v: unknown): unknown {
  if (typeof v !== "string") return v;
  return v.replace(/[\r\n]/g, " ").slice(0, 500); // anti log-injection + teto
}

export function logEvent(input: {
  level: "info" | "warn" | "error";
  event: string;            // ex.: "auth.login_failed", "access.denied", "ratelimit.hit"
  requestId: string;
  userId?: string;
  meta?: Record<string, unknown>;
}) {
  const line = JSON.stringify({ ts: new Date().toISOString(), ...input, meta: redact(input.meta ?? {}) });
  console[input.level](line);
}
```

### P2 — Trilha de auditoria em Postgres

```sql
CREATE TABLE audit_log (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL,
  action     text NOT NULL,          -- "artifact.delete", "connection.create", "role.change"
  resource   text NOT NULL,          -- "qa_artifacts:abc-123"
  created_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
-- Inserção apenas pelo servidor; usuário não lê auditoria de ninguém:
CREATE POLICY audit_no_select ON audit_log FOR SELECT USING (false);
CREATE INDEX idx_audit_user ON audit_log (user_id, created_at);
```

```typescript
// Nas operações críticas (delete, mudança de acesso, criação de integração):
await supabase.from("audit_log").insert({
  user_id: user.id, action: "connection.create", resource: `jira_connections:${conn.id}`,
});
// Falhou o insert? Logar e DECIDIR: operação crítica de verdade → abortar (fail closed).
```

### P3 — Eventos mínimos por fluxo

```text
auth.login_failed        warn   { email_domain }          ← domínio, não o e-mail
auth.password_changed    info   { }
access.denied            warn   { resource }
ratelimit.hit            warn   { action, limit }
ai.usage                 info   { function, tokens, costEstimate }
validation.rejected      info   { schema, fieldCount }    ← campos, não valores
server.error             error  { requestId }             ← stack vai no console.error
```

## Anti-padrões

```typescript
// ❌ NUNCA: headers/body inteiros no log [viola R2]
console.log("request:", req.headers, await req.text());
// Authorization, cookies e payload sensível acabam no agregador de logs.

// ❌ NUNCA: a chave junto do erro [viola R2]
console.error(`Gemini falhou com a key ${apiKey}:`, err);

// ❌ NUNCA: input cru no log [viola R4]
console.log(`busca: ${query}`);
// query = "x\n[ERROR] auth bypass detected" forja linhas de log.

// ❌ NUNCA: evento de segurança sem log [viola R1]
if (denied) return jsonError(403, "Acesso negado"); // e ninguém nunca soube
```

## Checklist

- [ ] Eventos de segurança do diff emitem `logEvent` estruturado?
- [ ] Nenhum secret/token/PII desnecessária em nenhum log?
- [ ] Valores externos sanitizados (sem `\n`, truncados)?
- [ ] Operações críticas gravam em `audit_log`?
- [ ] Existe alerta para 5xx em série / login falho em pico / gasto anômalo de IA?
- [ ] Retenção conhecida e suficiente para o dado em questão?
