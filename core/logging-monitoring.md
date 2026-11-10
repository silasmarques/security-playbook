---
owasp: [A09]
last-review: 2026-11-10
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
- **R5 — MUST** trilha de auditoria persistente para operações sensíveis: quem, o quê, em qual recurso, quando. Console some; auditoria fica. A trilha é **append-only** (nem o servidor edita ou apaga), o usuário auditado **não escreve nela** (senão forja o próprio histórico), e falha ao gravar **não é silenciosa**: em operação crítica, sem trilha não segue.
- **R6 — MUST** alerta minimamente viável: 5xx em série, pico de login falho, gasto anômalo de IA por usuário. Um webhook/e-mail simples já muda o jogo — o requisito é alguém ficar sabendo.
- **R7 — MUST** retenção definida: logs de segurança ≥ 90 dias onde a plataforma permitir; saber qual é o limite da plataforma (Supabase/Vercel) e exportar se precisar de mais.

## Padrões prontos

### P1 — Logger estruturado com redação automática

<!-- kit: kit/web/log.ts#logEvent -->
```typescript
const SENSITIVE_KEY = /key|token|secret|password|senha|authorization|cookie|credential|session|jwt|bearer|otp/i;
const MAX_VALUE = 500;
const MAX_DEPTH = 4;

/** Redige por NOME da chave, em qualquer profundidade. Valores de texto são
 *  achatados em uma linha (sem \r\n — o atacante não forja linhas de log) e
 *  truncados. */
export function redact(value: unknown, depth = 0): unknown {
  if (typeof value === "string") {
    // deno-lint-ignore no-control-regex
    return value.replace(/[\u0000-\u001f\u007f\u2028\u2029]+/g, " ").slice(0, MAX_VALUE);
  }
  if (value === null || typeof value !== "object") return value;
  if (depth >= MAX_DEPTH) return "[TRUNCATED]";
  if (Array.isArray(value)) return value.slice(0, 20).map((v) => redact(v, depth + 1));
  return Object.fromEntries(
    Object.entries(value as Record<string, unknown>).slice(0, 50).map(([k, v]) => [
      redact(k), SENSITIVE_KEY.test(k) ? "[REDACTED]" : redact(v, depth + 1),
    ]),
  );
}

export interface LogInput {
  level: "info" | "warn" | "error";
  event: string;            // ex.: "auth.login_failed", "access.denied", "ratelimit.hit"
  requestId: string;
  userId?: string;
  meta?: Record<string, unknown>;
}

export function formatLogLine(input: LogInput, now = new Date()): string {
  return JSON.stringify({
    ts: now.toISOString(),
    level: input.level,
    event: redact(input.event),
    requestId: redact(input.requestId),
    userId: input.userId === undefined ? undefined : redact(input.userId),
    meta: redact(input.meta ?? {}),
  });
}

export function logEvent(input: LogInput): void {
  console[input.level](formatLogLine(input));
}
```

### P2 — Trilha de auditoria (só o servidor grava; ninguém altera)

<!-- kit: kit/supabase/sql/03_audit_log.sql#audit_log -->
```sql
create table public.audit_log (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null,                 -- sem FK: a trilha sobrevive à exclusão da conta
  action     text not null check (char_length(action) between 1 and 100),   -- "artifact.delete", "role.change"
  resource   text not null check (char_length(resource) between 1 and 300), -- "qa_artifacts:abc-123"
  request_id text,
  meta       jsonb not null default '{}',
  created_at timestamptz not null default now()
);

alter table public.audit_log enable row level security;        -- sem policies: nega tudo a clientes
revoke all on public.audit_log from anon, authenticated;       -- e sem grants: segunda trava
create index audit_log_user_idx on public.audit_log (user_id, created_at desc);

-- Append-only até para o service_role: um bug (ou uma chave vazada) no servidor
-- não reescreve a história. Quem apaga auditoria é só o dono do banco, por retenção.
create function public.audit_log_append_only() returns trigger
language plpgsql set search_path = '' as $$
begin
  raise exception 'audit_log is append-only';
end $$;

create trigger audit_log_no_update_delete
  before update or delete on public.audit_log
  for each row execute function public.audit_log_append_only();

revoke truncate on public.audit_log from service_role;
```

<!-- kit: kit/supabase/guards.ts#writeAudit -->
```typescript
/** Grava a trilha de auditoria com o client de SERVIÇO (a tabela nega tudo a
 *  usuários). LANÇA se o insert falhar: operação crítica sem trilha não segue. */
export async function writeAudit(
  serviceClient: InsertClient,
  entry: { userId: string; action: string; resource: string; requestId: string; meta?: Record<string, unknown> },
): Promise<void> {
  const { error } = await serviceClient.from("audit_log").insert({
    user_id: entry.userId, action: entry.action, resource: entry.resource,
    request_id: entry.requestId, meta: entry.meta ?? {},
  });
  if (error) throw new Error("falha ao gravar audit_log"); // o boundary loga o detalhe
}
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

// ❌ NUNCA: gravar auditoria e ignorar o resultado [viola R5]
await supabase.from("audit_log").insert({ user_id: user.id, action: "role.change" });
// o client não lança: sem checar `error`, a trilha falha em silêncio

// ❌ NUNCA: evento de segurança sem log [viola R1]
if (denied) return jsonError(403, "Acesso negado"); // e ninguém nunca soube
```

## Checklist

- [ ] Eventos de segurança do diff emitem `logEvent` estruturado?
- [ ] Nenhum secret/token/PII desnecessária em nenhum log?
- [ ] Valores externos sanitizados (sem `\n`, truncados)?
- [ ] Operações críticas gravam na trilha de auditoria — append-only, escrita só pelo servidor, erro tratado?
- [ ] Existe alerta para 5xx em série / login falho em pico / gasto anômalo de IA?
- [ ] Retenção conhecida e suficiente para o dado em questão?
