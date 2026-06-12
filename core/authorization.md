---
owasp: [A01]
last-review: 2026-06-11
sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Insecure_Direct_Object_Reference_Prevention_Cheat_Sheet.html
---

# Autorização e Controle de Acesso

> Autenticação diz QUEM é; autorização diz O QUE pode. Broken Access Control é o A01 da OWASP — a falha mais comum e mais grave. Em 2025, SSRF foi absorvido por esta categoria: controlar para onde o SEU servidor pode fazer request também é controle de acesso.

## Regras

- **R1 — MUST** deny by default: toda rota, recurso e operação nega acesso até que uma checagem explícita prove o contrário. Ausência de regra = negado, nunca = permitido.
- **R2 — MUST** verificar autorização no servidor em TODO endpoint — inclusive os "internos", "temporários" ou "que só o frontend chama". Frontend esconde botão; não protege dado.
- **R3 — MUST** checar autorização em nível de objeto (anti-IDOR): além de "está logado", perguntar "este recurso específico pertence/está autorizado para este `auth.uid()`?". Toda busca por ID carrega filtro de dono.
- **R4 — MUST** centralizar a checagem de acesso em um helper único, chamado por TODAS as funções no mesmo ponto do fluxo. Checagem copiada à mão é checagem esquecida — em auditoria real de produção, a checagem de acesso existia em apenas parte das funções, deixando bypass real nas demais.
- **R5 — NEVER** derivar papel/permissão de payload do cliente (body, header custom, claim não verificada). Papel vem do banco ou de claim assinada e verificada.
- **R6 — MUST** validar toda URL de saída construída com dado externo (proxy, webhook, "buscar essa URL") contra SSRF: allowlist de protocolo (`http/https`), bloqueio de hostnames internos, bloqueio de IPs privados/link-local/metadata **em todas as formas** (decimal, hex, octal, comprimida, IPv4-mapped IPv6), e redirects revalidados hop a hop.
- **R7 — MUST** reavaliar autorização após mudança de privilégio — não confiar em cache de sessão/claims antigas para decisões sensíveis.

## Padrões prontos

### P1 — Helper centralizado de acesso (padrão `requireAccess`)

```typescript
// _shared/access-control.ts — ÚNICA implementação, importada por toda função.
// Retorna null se ok, ou uma Response 403 pronta — impossível "esquecer o else".
export async function requireAccess(
  supabase: SupabaseClient,
  userId: string,
  options: { featureLabel?: string; corsHeaders?: Record<string, string> } = {},
): Promise<Response | null> {
  const { data, error } = await supabase.rpc("check_user_access", { _user_id: userId });
  if (error || data?.[0]?.can_access !== true) {
    const message = options.featureLabel
      ? `Usuário sem acesso a ${options.featureLabel}`
      : "Usuário sem acesso";
    return new Response(JSON.stringify({ error: message }), {
      status: 403,
      headers: { ...(options.corsHeaders ?? {}), "Content-Type": "application/json" },
    });
  }
  return null;
}

// Uso no topo de TODA função, logo após autenticar:
const denied = await requireAccess(supabase, user.id, { featureLabel: "Consultor QA", corsHeaders });
if (denied) return denied;
```

### P2 — Validação SSRF de URL de saída

Estratégia em camadas (extraída de um validador de produção auditado):

```typescript
export function validateOutboundUrl(rawUrl: unknown): { ok: true } | { ok: false; reason: string } {
  if (typeof rawUrl !== "string" || rawUrl.length === 0 || rawUrl.length > 8192) {
    return { ok: false, reason: "URL ausente, inválida ou longa demais" };
  }
  let url: URL;
  try { url = new URL(rawUrl); } catch { return { ok: false, reason: "parse falhou" }; }

  // 1) Só http/https — nunca file:, gopher:, ftp:
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: `protocolo não permitido: ${url.protocol}` };
  }
  const host = url.hostname.toLowerCase();

  // 2) Hostnames internos por nome e por sufixo
  const blockedNames = new Set(["localhost", "metadata.google.internal", "metadata.azure.com", "instance-data.ec2.internal"]);
  const blockedSuffixes = [".internal", ".local", ".supabase.co", ".supabase.in"];
  if (blockedNames.has(host)) return { ok: false, reason: `hostname bloqueado: ${host}` };
  if (blockedSuffixes.some((s) => host.endsWith(s))) return { ok: false, reason: `sufixo interno: ${host}` };

  // 3) IP literal — NORMALIZAR antes de checar. Bypasses reais cobertos:
  //    2130706433 (decimal) = 0x7f000001 (hex) = 0177.0.0.1 (octal) = 127.1
  //    (comprimido) = [::ffff:127.0.0.1] (IPv4-mapped IPv6) = 127.0.0.1
  //    Checar faixas: 0/8, 10/8, 100.64/10, 127/8, 169.254/16 (metadata!),
  //    172.16/12, 192.0.0/24, 192.168/16, 198.18/15, 224/4; IPv6: ::1, fc00::/7, fe80::/10.
  //    → a implementação completa precisa normalizar TODAS as formas acima antes de checar.
  return { ok: true };
}
```

```typescript
// 4) Camada do fetch: redirects revalidados manualmente (fecha redirect → IP privado)
const res = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(10_000) });
if (res.status >= 300 && res.status < 400) {
  const next = res.headers.get("location");
  const check = validateOutboundUrl(new URL(next!, url).href); // revalida CADA hop
  if (!check.ok) throw new Error(`redirect bloqueado: ${check.reason}`);
}
```

> Limitação conhecida: validação por string não previne DNS rebinding (hostname que
> resolve público no check e privado no fetch). Mitigação: revalidação por hop +
> allowlist de domínios quando o destino é conhecido (ex.: só `*.atlassian.net`).

### P3 — Autorização em nível de objeto (anti-IDOR)

```typescript
// O filtro de dono acompanha SEMPRE o filtro de ID — mesmo com RLS ativa
// (defesa em profundidade; e obrigatório se o client usa service_role).
const { data: doc } = await supabase
  .from("qa_documents")
  .select("id, title, content")
  .eq("id", requestedId)
  .eq("user_id", user.id)   // ← sem isto, qualquer ID válido de OUTRO usuário vaza
  .maybeSingle();

if (!doc) return jsonError(404, "Recurso não encontrado"); // 404, não 403: não confirmar existência
```

## Anti-padrões

```typescript
// ❌ NUNCA: buscar por ID sem filtro de dono [viola R3]
const doc = await db.from("qa_documents").select().eq("id", body.docId).single();
// IDOR clássico: iterar docId lê os documentos de todo mundo.

// ❌ NUNCA: papel vindo do cliente [viola R5]
if (req.headers.get("x-user-role") === "admin") { /* ... */ }
if (body.isAdmin) { /* ... */ }

// ❌ NUNCA: fetch direto de URL do usuário [viola R6]
const data = await fetch(body.webhookUrl); // SSRF: body.webhookUrl = http://169.254.169.254/...

// ❌ NUNCA: checagem de acesso "só nas funções importantes" [viola R4]
// (lacuna real de auditoria: usuário bloqueado seguia consumindo as funções de IA
//  que não chamavam check_user_access)
```

## Checklist

- [ ] Todo endpoint novo chama o helper de acesso centralizado logo após autenticar?
- [ ] Toda busca por ID filtra por dono (`user_id = auth.uid()`)?
- [ ] Nenhum papel/permissão lido de body/header do cliente?
- [ ] Fetch com destino dinâmico passa pelo validador SSRF, com redirects revalidados?
- [ ] Recurso de outro usuário responde 404 (sem confirmar existência)?
- [ ] Negação é o comportamento default quando a checagem falha ou erra?
