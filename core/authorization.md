---
owasp: [A01]
last-review: 2026-11-10
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
- **R3 — MUST** checar autorização em nível de objeto (anti-IDOR): além de "está logado", perguntar "este recurso específico pertence a quem está chamando?". Toda busca por ID carrega filtro de dono.
- **R4 — MUST** centralizar a checagem de acesso em um helper único, chamado por TODAS as funções no mesmo ponto do fluxo. Checagem copiada à mão é checagem esquecida — em auditoria real de produção, ela existia em apenas parte das funções, deixando bypass nas demais.
- **R5 — NEVER** derivar papel/permissão de dado que o usuário controla: body, header custom, claim não verificada **nem claim assinada que o próprio usuário pode editar** (ex.: `user_metadata` na Supabase — assinada, mas escrita pelo cliente). Papel vem do banco ou de claim que só o servidor escreve.
- **R6 — MUST** validar toda URL de saída construída com dado externo (proxy, webhook, "buscar essa URL") contra SSRF: só `http/https`, sem credenciais embutidas, hostnames internos bloqueados, IPs privados/link-local/metadata bloqueados **em todas as formas** (decimal, hex, octal, comprimida, IPv4 embutido em IPv6), redirects revalidados hop a hop e corpo da resposta com teto de bytes. Quando o destino é conhecido, allowlist de host.
- **R7 — MUST** reavaliar autorização após mudança de privilégio — não confiar em cache de sessão/claims antigas para decisões sensíveis.
- **R8 — MUST** em sistema com organizações/times (multi-tenant), o filtro de tenant é tão obrigatório quanto o de dono: toda query carrega o tenant derivado da sessão — nunca do request — e a associação usuário↔tenant é conferida a cada chamada.

## Padrões prontos

### P1 — Helper centralizado de acesso

A decisão mora em um lugar só (uma função no banco, uma classe de policy); o handler pergunta e obedece. O helper é **fail closed**: erro, resposta estranha ou banco fora do ar negam.

<!-- kit: kit/supabase/guards.ts#requireAccess -->
```typescript
/** ÚNICA implementação da checagem de acesso; toda função chama logo após
 *  autenticar. `true` = pode seguir. A RPC `check_user_access` roda com o token
 *  do chamador e decide por `auth.uid()` — a função não recebe o id por parâmetro. */
export async function requireAccess(client: RpcClient): Promise<boolean> {
  try {
    const { data, error } = await client.rpc("check_user_access");
    return !error && data === true; // estritamente `true`: null, "true", 1, [] → negado
  } catch {
    return false; // banco fora do ar NÃO vira "todo mundo passa"
  }
}
```

Na stack Supabase, a função consultada é esta — note que a identidade vem de `auth.uid()`, nunca de parâmetro:

<!-- kit: kit/supabase/sql/01_profiles_access.sql#check_user_access -->
```sql
-- SECURITY DEFINER: roda como o dono e ignora a RLS de quem chama. Por isso:
--   1. `search_path = ''` e todo objeto com schema explícito;
--   2. identidade vem de auth.uid() — NUNCA de parâmetro;
--   3. EXECUTE revogado de public e anon (o default libera para todos).
create function public.check_user_access() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.profiles p
    where p.user_id = auth.uid() and p.blocked_at is null
  );
$$;

revoke execute on function public.check_user_access() from public, anon;
grant execute on function public.check_user_access() to authenticated;
```

### P2 — Validação SSRF de URL de saída

Implementação completa, coberta por 58 casos de teste (cada forma de IP da R6 é um caso):

<!-- kit: kit/web/ssrf.ts#validateOutboundUrl -->
```typescript
export function validateOutboundUrl(rawUrl: unknown, policy: OutboundPolicy = {}): UrlCheck {
  if (typeof rawUrl !== "string" || rawUrl.length === 0 || rawUrl.length > MAX_URL_LENGTH) {
    return { ok: false, reason: "URL ausente, inválida ou longa demais" };
  }
  let url: URL;
  try { url = new URL(rawUrl); } catch { return { ok: false, reason: "parse falhou" }; }

  // 1) Só http/https — nunca file:, gopher:, ftp:, data:
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: `protocolo não permitido: ${url.protocol}` };
  }
  // 2) Sem credenciais na URL (http://user:pass@host confunde parsers e vaza em log)
  if (url.username !== "" || url.password !== "") {
    return { ok: false, reason: "credenciais na URL não são permitidas" };
  }

  // O parser WHATWG já normalizou o host: minúsculas, IPv4 em qualquer base
  // (2130706433, 0x7f000001, 0177.0.0.1, 127.1) vira 127.0.0.1.
  const host = url.hostname.replace(/\.$/, "");

  // 3) Destino conhecido? Allowlist vence tudo — é a única defesa contra DNS rebinding.
  if (policy.allowedHosts) {
    return hostAllowed(host, policy.allowedHosts)
      ? { ok: true, url }
      : { ok: false, reason: `host fora da allowlist: ${host}` };
  }

  // 4) IP literal: classificar pela faixa, v4 e v6 (incluindo v4 embutido em v6)
  if (host.startsWith("[")) {
    const bytes = parseV6(host.slice(1, -1));
    if (!bytes || isBlockedV6(bytes)) return { ok: false, reason: `IPv6 bloqueado: ${host}` };
    return { ok: true, url };
  }
  const v4 = parseV4(host);
  if (v4) {
    return isBlockedV4(v4) ? { ok: false, reason: `IPv4 bloqueado: ${host}` } : { ok: true, url };
  }

  // 5) Hostnames internos por nome e por sufixo
  const suffixes = [...BLOCKED_SUFFIXES, ...(policy.extraBlockedSuffixes ?? [])];
  if (BLOCKED_NAMES.has(host) || !host.includes(".")) {
    return { ok: false, reason: `hostname interno: ${host}` };
  }
  if (suffixes.some((s) => host.endsWith(s))) return { ok: false, reason: `sufixo interno: ${host}` };

  return { ok: true, url };
}
```

O fetch que acompanha: redirects seguidos à mão, cada hop revalidado, um timeout para a cadeia inteira.

<!-- kit: kit/web/ssrf.ts#safeFetch -->
```typescript
/** fetch para URL de origem externa: valida, segue redirects À MÃO revalidando
 *  cada hop, e aplica um timeout único à cadeia toda. */
export async function safeFetch(rawUrl: unknown, opts: SafeFetchOptions = {}): Promise<Response> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const maxRedirects = opts.maxRedirects ?? 3;
  const signal = AbortSignal.timeout(opts.timeoutMs ?? 10_000);

  let current: unknown = rawUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const check = validateOutboundUrl(current, opts);
    if (!check.ok) throw new OutboundBlockedError(check.reason);

    if (opts.resolveHost && !/^[\d.]+$|^\[/.test(check.url.hostname)) {
      const ips = await opts.resolveHost(check.url.hostname);
      if (ips.length === 0 || ips.some(isBlockedIp)) {
        throw new OutboundBlockedError(`host resolve para IP interno: ${check.url.hostname}`);
      }
    }

    const res = await fetchImpl(check.url, { ...opts.init, redirect: "manual", signal });
    if (res.status < 300 || res.status >= 400) return res;

    const location = res.headers.get("location");
    await res.body?.cancel();
    if (!location) throw new OutboundBlockedError("redirect sem Location");
    current = new URL(location, check.url).href; // relativo → absoluto, e volta ao topo
  }
  throw new OutboundBlockedError(`mais de ${maxRedirects} redirects`);
}
```

> **Limite conhecido — DNS rebinding.** Validar a URL não impede que um hostname público *resolva* para IP privado. Em ordem de força: `allowedHosts` (a única defesa completa, quando o destino é conhecido) › `resolveHost` (confere os IPs resolvidos; ainda existe uma janela entre conferir e conectar) › nada. O arquivo completo ([kit/web/ssrf.ts](../kit/web/ssrf.ts)) traz também `readBodyCapped`, para a resposta não esgotar memória.

### P3 — Autorização em nível de objeto (anti-IDOR)

<!-- ilustrativo -->
```typescript
// O filtro de dono acompanha SEMPRE o filtro de ID — mesmo com RLS ativa
// (defesa em profundidade; e obrigatório se o client ignora RLS, como o service_role).
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
if (user.user_metadata.role === "admin") { /* ... */ } // assinado, mas o usuário escreve

// ❌ NUNCA: fetch direto de URL do usuário [viola R6]
const data = await fetch(body.webhookUrl); // SSRF: body.webhookUrl = http://169.254.169.254/...

// ❌ NUNCA: "validador" que só confere o protocolo [viola R6]
if (url.startsWith("https://")) await fetch(url); // https://127.0.0.1/ e redirect para a rede interna passam

// ❌ NUNCA: checagem de acesso "só nas funções importantes" [viola R4]
// (lacuna real de auditoria: usuário bloqueado seguia consumindo as funções de IA
//  que não chamavam a checagem)

// ❌ NUNCA: tenant vindo do request [viola R8]
const { orgId } = await req.json(); // trocar o orgId = ler os dados de outra empresa
```

## Checklist

- [ ] Todo endpoint novo chama o helper de acesso centralizado logo após autenticar?
- [ ] Toda busca por ID filtra por dono (e por tenant, se houver)?
- [ ] Nenhum papel/permissão lido de body, header ou claim editável pelo usuário?
- [ ] Fetch com destino dinâmico passa por `safeFetch` (ou equivalente com redirect revalidado e teto de resposta)?
- [ ] Recurso de outro usuário responde 404 (sem confirmar existência)?
- [ ] Negação é o comportamento default quando a checagem falha ou erra?
