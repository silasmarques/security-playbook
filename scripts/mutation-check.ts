// "Toda verificação precisa poder falhar" (core/security-testing.md R7/R9),
// aplicado a este repositório: cada mutação abaixo QUEBRA um controle ou uma
// garantia, e o comando indicado tem de falhar. Mutante que sobrevive = a suíte
// não protege aquilo, e este script falha.
//
//   deno task mutation            (roda numa cópia temporária; não toca o repo)
//   deno task mutation -- --only ssrf
//
// A lista é curada, não gerada: uma mutação por garantia que a norma anuncia.
// Mutação cujo trecho-alvo não existe mais é ERRO ("obsoleta") — a lista não
// pode apodrecer em silêncio.

interface Mutation {
  id: string;
  what: string;       // a garantia que está sendo quebrada
  file: string;
  find: string;
  replace: string;
  cmd: string[];      // argumentos do deno; tem de sair com código ≠ 0
}

const T = ["test", "--allow-read", "--allow-write", "--allow-env", "--allow-net", "--allow-run"];
const kit = (f: string) => [...T, `kit/tests/${f}.test.ts`];
const DOCS = ["run", "--allow-read", "scripts/verify-docs.ts"];
const SYNC = ["run", "--allow-read", "scripts/sync-snippets.ts", "--check"];
const SCAN = [...T, "explore/scan.test.ts"];

const MUTATIONS: Mutation[] = [
  // ---- kit/web
  { id: "ssrf-metadata", what: "SSRF bloqueia link-local/metadata", file: "kit/web/ssrf.ts",
    find: `["169.254.0.0", 16],`, replace: ``, cmd: kit("ssrf") },
  { id: "ssrf-v6-mapped", what: "SSRF bloqueia IPv4 embutido em IPv6", file: "kit/web/ssrf.ts",
    find: `if (allZero(0, 10) && b[10] === 0xff && b[11] === 0xff) return embeddedV4(12);`, replace: ``, cmd: kit("ssrf") },
  { id: "ssrf-credentials", what: "SSRF rejeita credenciais na URL", file: "kit/web/ssrf.ts",
    find: `if (url.username !== "" || url.password !== "") {`, replace: `if (false) {`, cmd: kit("ssrf") },
  { id: "ssrf-redirect", what: "cada hop de redirect é revalidado", file: "kit/web/ssrf.ts",
    find: `current = new URL(location, check.url).href; // relativo → absoluto, e volta ao topo`,
    replace: `return await fetchImpl(new URL(location, check.url), { ...opts.init, signal });`, cmd: kit("ssrf") },
  { id: "cors-echo", what: "CORS só ecoa origem da allowlist", file: "kit/web/cors.ts",
    find: `if (allowed.has(origin)) {`, replace: `if (origin) {`, cmd: kit("http") },
  { id: "headers-override", what: "security headers não são sobrescritos", file: "kit/web/http.ts",
    find: `headers: { ...extraHeaders, ...API_SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8" },`,
    replace: `headers: { ...API_SECURITY_HEADERS, "Content-Type": "application/json; charset=utf-8", ...extraHeaders },`, cmd: kit("http") },
  { id: "boundary-leak", what: "boundary não devolve a mensagem da exceção", file: "kit/web/error-boundary.ts",
    find: `return jsonError(500, "Erro interno. Tente novamente.", extra, requestId);`,
    replace: `return jsonError(500, String(error), extra, requestId);`, cmd: kit("http") },
  { id: "body-cap", what: "body acima do teto é recusado", file: "kit/web/http.ts",
    find: `if (total > maxBytes) { await reader.cancel(); return undefined; }`, replace: ``, cmd: kit("http") },
  { id: "cipher-aad", what: "dado cifrado é amarrado ao contexto (AAD)", file: "kit/web/crypto.ts",
    find: `{ name: "AES-GCM", iv: blob.subarray(0, IV_BYTES), additionalData: enc.encode(context) },`,
    replace: `{ name: "AES-GCM", iv: blob.subarray(0, IV_BYTES), additionalData: enc.encode("") },`, cmd: kit("crypto") },
  { id: "cipher-key-size", what: "chave de tamanho errado falha o boot", file: "kit/web/crypto.ts",
    find: `if (raw.length !== 32) throw new Error(`, replace: `if (raw.length === 0) throw new Error(`, cmd: kit("crypto") },
  { id: "payload-replay", what: "payload assinado expira", file: "kit/web/crypto.ts",
    find: `if (now - iat > (opts.maxAgeMs ?? 10 * 60_000)) return null; // velho demais → replay`, replace: ``, cmd: kit("crypto") },
  { id: "payload-signature", what: "assinatura é conferida antes de ler o payload", file: "kit/web/crypto.ts",
    find: `if (!(await hmacVerify(body, sig, secret))) return null;   // assinatura ANTES de ler o conteúdo`, replace: ``, cmd: kit("crypto") },
  { id: "wrap-neutralize", what: "conteúdo não consegue forjar o delimitador", file: "kit/web/untrusted-content.ts",
    find: `safe = safe.replace(/<<</g, "‹‹‹").replace(/>>>/g, "›››");`, replace: ``, cmd: kit("llm") },
  { id: "risk-unicode", what: "score detecta troca de papel em português", file: "kit/web/injection-risk.ts",
    find: "const B = String.raw`(?<![\\p{L}\\p{N}_])`;\nconst E = String.raw`(?![\\p{L}\\p{N}_])`;",
    replace: "const B = String.raw`\\b`;\nconst E = String.raw`\\b`;", cmd: kit("llm") },
  { id: "log-redact", what: "chaves sensíveis são redigidas no log", file: "kit/web/log.ts",
    find: `SENSITIVE_KEY.test(k) ? "[REDACTED]" : redact(v, depth + 1),`, replace: `redact(v, depth + 1),`, cmd: kit("misc") },
  { id: "log-injection", what: "quebra de linha não forja linha de log", file: "kit/web/log.ts",
    find: `.replace(/[\\u0000-\\u001f\\u007f\\u2028\\u2029]+/g, " ")`, replace: ``, cmd: kit("misc") },
  { id: "upload-sniff", what: "upload confere o conteúdo do arquivo", file: "kit/web/upload.ts",
    find: `if (head.length === 0 || !spec.sniff(head)) {`, replace: `if (head.length === 0) {`, cmd: kit("misc") },
  { id: "retry-4xx", what: "retry não repete erro do cliente", file: "kit/web/resilience.ts",
    find: `const RETRYABLE = new Set([0, 408, 429, 500, 502, 503, 504]);`, replace: `const RETRYABLE = new Set([0, 400, 403, 408, 429, 500, 502, 503, 504]);`, cmd: kit("misc") },
  { id: "safe-next", what: "redirect pós-login não sai da origem", file: "kit/web/safe-url.ts",
    find: `if (url.origin !== new URL(origin).origin) return "/";`, replace: ``, cmd: kit("misc") },
  { id: "schema-extra", what: "schema rejeita campo desconhecido", file: "kit/supabase/function-template/schema.ts",
    find: `if (Object.keys(rec).some((k) => !ALLOWED_KEYS.has(k))) return null;`, replace: ``, cmd: kit("schema") },
  // ---- kit/supabase
  { id: "guard-fail-open", what: "guarda de acesso é fail-closed", file: "kit/supabase/guards.ts",
    find: `return !error && data === true; // estritamente \`true\`: null, "true", 1, [] → negado`, replace: `return !error && data !== false;`, cmd: kit("misc") },
  { id: "audit-silent", what: "falha na auditoria não é silenciosa", file: "kit/supabase/guards.ts",
    find: `if (error) throw new Error("falha ao gravar audit_log"); // o boundary loga o detalhe`, replace: ``, cmd: kit("misc") },
  { id: "sql-insert-owner", what: "RLS impede criar linha em nome de outro", file: "kit/supabase/sql/04_owned_table_template.sql",
    find: `to authenticated with check ((select auth.uid()) = user_id);`, replace: `to authenticated with check (true);`, cmd: kit("sql") },
  { id: "sql-select-owner", what: "RLS impede ler linha de outro", file: "kit/supabase/sql/04_owned_table_template.sql",
    find: `create policy "notas: ler as próprias" on public.qa_notes for select\n  to authenticated using ((select auth.uid()) = user_id);`,
    replace: `create policy "notas: ler as próprias" on public.qa_notes for select\n  to authenticated using (true);`, cmd: kit("sql") },
  { id: "sql-column-priv", what: "usuário não escreve em coluna de poder", file: "kit/supabase/sql/01_profiles_access.sql",
    find: `revoke insert, update, delete on public.profiles from anon, authenticated;\ngrant update (display_name) on public.profiles to authenticated;`, replace: ``, cmd: kit("sql") },
  { id: "sql-definer-revoke", what: "anon não executa função privilegiada", file: "kit/supabase/sql/01_profiles_access.sql",
    find: `revoke execute on function public.check_user_access() from public, anon;`, replace: ``, cmd: kit("sql") },
  { id: "sql-blocked", what: "usuário bloqueado perde o acesso", file: "kit/supabase/sql/01_profiles_access.sql",
    find: `where p.user_id = auth.uid() and p.blocked_at is null`, replace: `where p.user_id = auth.uid()`, cmd: kit("sql") },
  { id: "sql-ratelimit", what: "rate limit nega acima do limite", file: "kit/supabase/sql/02_rate_limit.sql",
    find: `return _count <= _rule.max_calls;`, replace: `return true;`, cmd: kit("sql") },
  { id: "sql-counters-locked", what: "usuário não zera os próprios contadores", file: "kit/supabase/sql/02_rate_limit.sql",
    find: `alter table public.usage_counters enable row level security;\nrevoke all on public.rate_limits, public.usage_counters from anon, authenticated;`,
    replace: `create policy aberta on public.usage_counters for all to authenticated using (true) with check (true);\nalter table public.usage_counters enable row level security;`, cmd: kit("sql") },
  { id: "sql-audit-append", what: "auditoria é append-only", file: "kit/supabase/sql/03_audit_log.sql",
    find: `  before update or delete on public.audit_log`, replace: `  before truncate on public.audit_log`, cmd: kit("sql") },
  { id: "sql-audit-forge", what: "usuário não escreve na própria trilha", file: "kit/supabase/sql/03_audit_log.sql",
    find: `revoke all on public.audit_log from anon, authenticated;       -- e sem grants: segunda trava`,
    replace: `create policy forja on public.audit_log for insert to authenticated with check (true);`, cmd: kit("sql") },
  { id: "sql-storage", what: "storage isola por pasta do usuário", file: "kit/supabase/sql/05_storage_policies.sql",
    find: `  with check (bucket_id = 'documents' and (storage.foldername(name))[1] = (select auth.uid())::text);`,
    replace: `  with check (bucket_id = 'documents');`, cmd: kit("sql") },
  // ---- explorador
  { id: "explore-rls", what: "explorador acusa tabela sem RLS", file: "explore/supabase/db-checks.ts",
    find: `    if (!t.rls) {`, replace: `    if (false) {`, cmd: SCAN },
  { id: "explore-catalog", what: "explorador acusa policy sem condição", file: "explore/supabase/db-checks.ts",
    find: `if ((p.qual === "true" && p.cmd !== "INSERT") || p.check === "true") {`, replace: `if (false) {`, cmd: SCAN },
  { id: "explore-mask", what: "relatório não copia segredo inteiro", file: "explore/code-checks.ts",
    find: "const mask = (s: string) => s.length <= 10 ? s.slice(0, 3) + \"…\" : `${s.slice(0, 8)}…(${s.length} caracteres)`;",
    replace: "const mask = (s: string) => s;", cmd: SCAN },
  { id: "explore-false-positive", what: "explorador não acusa a isca corrigida", file: "lab/cobaia/supabase/migrations/20260301000000_hardening.sql",
    find: `alter table public.access_log enable row level security;`, replace: ``, cmd: SCAN },
  { id: "explore-partial", what: "migration que falha é reportada", file: "explore/scan.ts",
    find: `notes.push("Análise de banco PARCIAL:`, replace: `void ("Análise de banco PARCIAL:`, cmd: SCAN },
  // ---- documentação
  { id: "docs-drift", what: "bloco da norma idêntico ao kit testado", file: "core/authorization.md",
    find: `  if (policy.allowedHosts) {`, replace: `  if (policy.allowedHosts?.length) {`, cmd: SYNC },
  { id: "docs-rule-ref", what: "referência cruzada aponta para regra que existe", file: "owasp-mapping.md",
    find: `(api-security R9)`, replace: `(api-security R99)`, cmd: DOCS },
  { id: "docs-link", what: "link relativo resolve", file: "SECURITY.md",
    find: `[core/secure-design.md](core/secure-design.md) |`, replace: `[core/secure-design.md](core/nao-existe.md) |`, cmd: DOCS },
  { id: "docs-unsourced-block", what: "padrão pronto sem origem é recusado", file: "stack/supabase-rls.md",
    find: `<!-- kit: kit/supabase/sql/04_owned_table_template.sql#owned_table -->\n`, replace: ``, cmd: DOCS },
  { id: "docs-count", what: "contagem anunciada bate com a realidade", file: "README.md",
    find: `17 regras inegociáveis`, replace: `99 regras inegociáveis`, cmd: DOCS },
  { id: "docs-matrix", what: "matriz OWASP bate com as tags", file: "core/authorization.md",
    find: `owasp: [A01]`, replace: `owasp: [A01, A04]`, cmd: DOCS },
];

// ---------------------------------------------------------------- execução
const ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const only = Deno.args.includes("--only") ? Deno.args[Deno.args.indexOf("--only") + 1] : undefined;
const SKIP = new Set([".git", "node_modules", ".claude"]);

async function copyTree(from: string, to: string) {
  await Deno.mkdir(to, { recursive: true });
  for await (const e of Deno.readDir(from)) {
    if (SKIP.has(e.name)) continue;
    if (e.isDirectory) await copyTree(`${from}/${e.name}`, `${to}/${e.name}`);
    else if (e.isFile) await Deno.copyFile(`${from}/${e.name}`, `${to}/${e.name}`);
  }
}

async function run(cwd: string, args: string[]): Promise<number> {
  const out = await new Deno.Command(Deno.execPath(), { args, cwd, stdout: "null", stderr: "null", env: { NO_COLOR: "1" } }).output();
  return out.code;
}

const work = await Deno.makeTempDir({ prefix: "playbook-mutation-" });
const survivors: string[] = [], stale: string[] = [];
let killed = 0;
try {
  await copyTree(ROOT, work);

  // Sanidade: sem mutação, cada comando PASSA. Senão "falhou" não quer dizer nada.
  const selected = MUTATIONS.filter((m) => !only || m.id.includes(only));
  const baselines = new Map<string, string[]>();
  for (const m of selected) baselines.set(m.cmd.join(" "), m.cmd);
  for (const [key, cmd] of baselines) {
    if ((await run(work, cmd)) !== 0) {
      console.error(`mutation-check: o comando já falha SEM mutação — conserte antes: deno ${key}`);
      Deno.exit(1);
    }
  }

  for (const m of selected) {
    const path = `${work}/${m.file}`;
    const original = await Deno.readTextFile(path);
    if (original.split(m.find).length !== 2) {
      stale.push(`${m.id}: o trecho-alvo aparece ${original.split(m.find).length - 1}× em ${m.file} (esperado: 1)`);
      continue;
    }
    await Deno.writeTextFile(path, original.replace(m.find, m.replace));
    const code = await run(work, m.cmd);
    await Deno.writeTextFile(path, original);
    if (code === 0) { survivors.push(`${m.id}: quebrar "${m.what}" NÃO fez nada falhar`); console.log(`  SOBREVIVEU  ${m.id}`); }
    else { killed++; console.log(`  ok          ${m.id} — ${m.what}`); }
  }
} finally {
  await Deno.remove(work, { recursive: true });
}

if (stale.length || survivors.length) {
  console.error(`\nmutation-check: ${survivors.length} mutante(s) sobreviveram, ${stale.length} mutação(ões) obsoleta(s)\n`);
  for (const s of [...survivors, ...stale]) console.error(`  - ${s}`);
  Deno.exit(1);
}
console.log(`\nmutation-check OK: ${killed} controle(s) quebrados de propósito, ${killed} detectados pela suíte.`);
