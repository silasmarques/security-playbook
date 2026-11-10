import { assert, assertEquals, assertFalse } from "@std/assert";
import { scanProject } from "./scan.ts";
import { renderMarkdown } from "./report.ts";
import { LINE_RULES } from "./code-checks.ts";
import { openProject } from "./supabase/probe.ts";
import { installKit } from "../kit/install.ts";
import type { Finding } from "./types.ts";

const ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const COBAIA = `${ROOT}/lab/cobaia`;
const db = { sanitizeResources: false, sanitizeOps: false };

interface Falha { id: string; detector: string; regra?: string; arquivo?: string; linha?: number; objeto?: string }
const gabarito: { falhas: Falha[]; iscas: Array<{ onde: string }> } = JSON.parse(await Deno.readTextFile(`${ROOT}/lab/gabarito.json`));
const key = (rule: string, file?: string, line?: number, object?: string) => `${rule} @ ${file ?? ""}:${line ?? ""} ${object ?? ""}`.trim();

// ------------------------------------------------------------------ cobaia
Deno.test({ name: "cobaia: o explorador acha TODAS as falhas de padrão do gabarito e NADA além delas", ...db, fn: async () => {
  const report = await scanProject(COBAIA);
  const found = report.findings.map((f) => key(f.rule, f.file, f.line, f.object)).sort();
  const expected = gabarito.falhas.filter((f) => f.detector === "scan").map((f) => key(f.regra!, f.arquivo, f.linha, f.objeto)).sort();
  assertEquals(found.filter((k) => !expected.includes(k)), [], "achado fora do gabarito (falso positivo, ou falha nova a registrar)");
  assertEquals(expected.filter((k) => !found.includes(k)), [], "falha do gabarito que deixou de ser encontrada");
  assertEquals(report.coverage.migrationsFailed, []);
  assert(report.coverage.dbAnalyzed);
} });

Deno.test({ name: "cobaia: nenhuma isca é acusada", ...db, fn: async () => {
  const report = await scanProject(COBAIA);
  const clean = ["public.notes", "public.user_settings", "public.access_log", "public.is_active()", "public.my_recent_notes", "public.count_notes_like(_q text)", "storage.buckets/documents"];
  for (const f of report.findings) {
    assertFalse(clean.some((c) => f.object === c || f.object?.startsWith(`${c} /`) || f.object?.startsWith(`${c}.`)), `isca acusada: ${f.rule} ${f.object}`);
    assertFalse(["supabase/functions/health/index.ts", "src/components/SafeHtml.tsx", "src/lib/format.ts"].includes(f.file ?? ""), `isca acusada: ${f.rule} ${f.file}`);
  }
  // a isca "fetch para constante" não vira SSRF; run_export não é executável por anon
  assertFalse(report.findings.some((f) => f.rule === "C-FETCH-DYNAMIC-URL" && f.file?.includes("ai-summarize")));
  assertFalse(report.findings.some((f) => f.rule === "DB-DEFINER-ANON-EXEC" && f.object?.includes("run_export")));
} });

Deno.test({ name: "cobaia: exceção registrada no código sai em 'suppressed', com o motivo", ...db, fn: async () => {
  const report = await scanProject(COBAIA);
  assertEquals(report.suppressed.length, 1);
  assertEquals(report.suppressed[0]!.rule, "C-CORS-WILDCARD");
  assert(report.suppressed[0]!.reason.startsWith("endpoint público de status"));
} });

Deno.test({ name: "relatório: segredo encontrado nunca é copiado inteiro", ...db, fn: async () => {
  const md = renderMarkdown(await scanProject(COBAIA));
  const plantado = (await Deno.readTextFile(`${COBAIA}/supabase/functions/save-settings/index.ts`)).match(/eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+/)![0];
  assert(plantado.length > 60);
  assertFalse(md.includes(plantado));
  assertFalse(md.includes(plantado.slice(0, 40)));
  assert(md.includes(`${plantado.slice(0, 8)}…`));
  assert(md.includes("## Cobertura — o que foi e o que NÃO foi analisado"));
} });

// ------------------------------------------------------------------ o kit passa no próprio explorador
Deno.test({ name: "dogfood: projeto com o kit INSTALADO sai com ZERO achados, e o template instalado compila", ...db, fn: async () => {
  const dir = await Deno.makeTempDir({ prefix: "kit-instalado-" });
  try {
    await Deno.writeTextFile(`${dir}/.gitignore`, ".env\n.env.*\n!.env.example\nnode_modules/\n");
    const first = await installKit(dir, { sql: true, now: new Date("2026-01-01T00:00:00Z") });
    assert(first.written.includes("supabase/functions/_shared/ssrf.ts"));
    assert(first.written.includes("supabase/functions/_template/index.ts"));
    assertEquals(first.skipped, []);

    const report = await scanProject(dir);
    assertEquals(report.coverage.migrationsFailed, []);
    assertEquals(report.coverage.migrationsOutOfOrder, []);
    assertEquals(report.findings.map((f) => `${f.rule} ${f.file ?? f.object}:${f.line ?? ""}`), []);

    // os imports reescritos resolvem no layout de destino
    const check = await new Deno.Command(Deno.execPath(), {
      args: ["check", "--no-config", `${dir}/supabase/functions/_template/index.ts`], stdout: "piped", stderr: "piped",
    }).output();
    assertEquals(check.code, 0, new TextDecoder().decode(check.stderr));

    // reinstalar não sobrescreve o que o projeto já tem (e pode ter editado)
    await Deno.writeTextFile(`${dir}/supabase/functions/_shared/cors.ts`, "// editado pelo projeto\n");
    const second = await installKit(dir, { sql: false });
    assertEquals(second.written, []);
    assertEquals(await Deno.readTextFile(`${dir}/supabase/functions/_shared/cors.ts`), "// editado pelo projeto\n");
  } finally { await Deno.remove(dir, { recursive: true }); }
} });

Deno.test({ name: "núcleo universal: projeto sem Supabase tem código e config analisados, e o relatório diz que o banco ficou de fora", ...db, fn: async () => {
  const dir = await tempProject({
    "package.json": "{}",
    "server/routes.ts": 'app.get("/x", async (req, res) => { const r = await fetch(req.query.url); res.send(await r.text()); });\n',
  });
  try {
    const r = await scanProject(dir);
    assertFalse(r.coverage.dbAnalyzed);
    assert(r.coverage.notes.some((n) => n.includes("nenhum adaptador de banco")));
    assertEquals(r.findings.map((f) => f.rule).sort(), ["C-FETCH-DYNAMIC-URL", "C-FETCH-NO-TIMEOUT", "CFG-GITIGNORE-ENV", "CFG-NO-LOCKFILE"]);
  } finally { await Deno.remove(dir, { recursive: true }); }
} });

// ------------------------------------------------------------------ honestidade da cobertura
async function tempProject(files: Record<string, string>): Promise<string> {
  const dir = await Deno.makeTempDir({ prefix: "explore-" });
  for (const [path, content] of Object.entries(files)) {
    await Deno.mkdir(`${dir}/${path}`.replace(/\/[^/]+$/, ""), { recursive: true });
    await Deno.writeTextFile(`${dir}/${path}`, content);
  }
  return dir;
}

Deno.test({ name: "cobertura: migration que não aplica é REPORTADA — o resto ainda é analisado", ...db, fn: async () => {
  const dir = await tempProject({
    ".gitignore": ".env\n",
    "supabase/migrations/001_ok.sql": "create table public.aberta (id int);",
    "supabase/migrations/002_quebrada.sql": "create extension extensao_que_nao_existe; create table public.nunca_criada (id int);",
    "supabase/migrations/003_ok.sql": "create table public.outra (id int); alter table public.outra enable row level security; revoke all on public.outra from anon, authenticated;",
  });
  try {
    const r = await scanProject(dir);
    assertEquals(r.coverage.migrationsFailed.map((m) => m.file), ["supabase/migrations/002_quebrada.sql"]);
    assertEquals(r.coverage.migrationsApplied.length, 2);
    assert(r.coverage.notes.some((n) => n.includes("PARCIAL")));
    assertEquals(r.findings.filter((f) => f.rule === "DB-RLS-OFF").map((f) => f.object), ["public.aberta"]);
    assert(renderMarkdown(r).includes("Migration NÃO aplicada"));
  } finally { await Deno.remove(dir, { recursive: true }); }
} });

Deno.test({ name: "cobertura: projeto sem migrations diz que o banco NÃO foi analisado", ...db, fn: async () => {
  const dir = await tempProject({ ".gitignore": ".env\n", "src/a.ts": "export const a = 1;\n", "supabase/config.toml": 'project_id = "x"\n' });
  try {
    const r = await scanProject(dir);
    assertFalse(r.coverage.dbAnalyzed);
    assert(r.coverage.notes.some((n) => n.includes("NÃO foi analisado")));
    assertEquals(r.findings, []);
  } finally { await Deno.remove(dir, { recursive: true }); }
} });

Deno.test({ name: "catálogo vence regex: RLS desligada por migration POSTERIOR é acusada", ...db, fn: async () => {
  const dir = await tempProject({
    ".gitignore": ".env\n",
    "supabase/migrations/001.sql": "create table public.t (id int, user_id uuid); alter table public.t enable row level security;",
    "supabase/migrations/002.sql": "alter table public.t disable row level security;",
  });
  try {
    const r = await scanProject(dir);
    assertEquals(r.findings.filter((f) => f.rule === "DB-RLS-OFF").length, 1);
  } finally { await Deno.remove(dir, { recursive: true }); }
} });

// ------------------------------------------------------------------ regras de linha: cada uma dispara e cada uma se cala
const CASOS: Record<string, { file: string; hit: string[]; miss: string[] }> = {
  "C-SECRET-HARDCODED": { file: "supabase/functions/x/index.ts",
    // Amostras montadas por concatenação: o arquivo não contém literal com formato de chave
    // real (evita bloqueio por proteção de push e ruído em secret scanners).
    hit: [`const k = "${"sk-" + "proj-abcdefghijklmnopqrstuvwx"}";`, `const g = "${"AI" + "zaSyA1234567890abcdefghijklmnopqrstuv"}";`,
      `${"-----BEGIN " + "PRIVATE KEY-----"}`, `key: "${"sb_" + "secret_abcdefghij1234"}"`, `const s = "${"sk_" + "live_abcdefghijklmnopqrstuvwx"}";`],
    miss: ['const k = Deno.env.get("OPENAI_KEY");', 'const s = "sk-curta";', 'const anon = "sb_publishable_abcdefghij1234";'] },
  "C-SECRET-IN-BUNDLE": { file: "src/lib/x.ts",
    hit: ["import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY", "const k = SERVICE_ROLE_KEY;", "VITE_STRIPE_SECRET=abc"],
    miss: ["import.meta.env.VITE_SUPABASE_ANON_KEY", "import.meta.env.VITE_SUPABASE_URL"] },
  "C-CORS-WILDCARD": { file: "supabase/functions/x/index.ts",
    hit: ['"Access-Control-Allow-Origin": "*",', "headers.set('Access-Control-Allow-Origin', '*')"],
    miss: ['"Access-Control-Allow-Origin": origin,', '"Access-Control-Allow-Headers": "*"'] },
  "C-ENV-FALLBACK": { file: "supabase/functions/x/index.ts",
    hit: ['const k = Deno.env.get("ENCRYPTION_KEY") ?? "dev-key";', "const t = process.env.API_TOKEN || 'abc';"],
    miss: ['const k = Deno.env.get("ENCRYPTION_KEY")!;', 'const env = Deno.env.get("APP_ENV") ?? "dev";', 'const o = Deno.env.get("ALLOWED_ORIGINS") ?? "";'] },
  "C-GETSESSION-SERVER": { file: "supabase/functions/x/index.ts",
    hit: ["const { data } = await supabase.auth.getSession();"], miss: ["const { data } = await supabase.auth.getUser();"] },
  "C-JWT-UNVERIFIED": { file: "supabase/functions/x/index.ts",
    hit: ["const c = jwtDecode(token);", "const c = jwtDecode<Claims>(token);", 'const p = JSON.parse(atob(token.split(".")[1]));'],
    miss: ['import { jwtDecode } from "npm:jwt-decode@4";', "const { data } = await supabase.auth.getUser(token);"] },
  "C-IDENTITY-FROM-BODY": { file: "supabase/functions/x/index.ts",
    hit: ["const { userId, docId } = await req.json();", "const id = body.user_id;", 'const u = url.searchParams.get("user_id");'],
    miss: ["const { docId } = await req.json();", "const id = user.id;", ".eq('user_id', user.id)"] },
  "C-DANGEROUS-HTML": { file: "src/components/Bio.tsx",
    hit: ["<div dangerouslySetInnerHTML={{ __html: bio }} />", "el.innerHTML = texto;"], miss: ["<div>{bio}</div>", "el.textContent = texto;"] },
  "C-REHYPE-RAW": { file: "src/components/Md.tsx",
    hit: ["<ReactMarkdown rehypePlugins={[rehypeRaw]}>{x}</ReactMarkdown>"], miss: ['import rehypeRaw from "rehype-raw";', "<ReactMarkdown rehypePlugins={[rehypeSanitize]}>{x}</ReactMarkdown>"] },
  "C-OPEN-REDIRECT": { file: "src/pages/Login.tsx",
    hit: ['navigate(searchParams.get("next") ?? "/");', 'window.location.href = searchParams.get("redirect")!;'],
    miss: ['const destino = safeNext(searchParams.get("next"), window.location.origin);', "navigate(destino);", 'navigate("/painel");'] },
  "C-SQL-CONCAT": { file: "supabase/functions/x/index.ts",
    hit: ["const q = `select * from users where email = '${email}'`;", "db.query(`DELETE FROM notes WHERE id = ${id}`)"],
    miss: ["const q = sql`select * from users where email = ${email}`;", "const msg = `usuário ${nome} selecionado`;", 'supabase.from("users").select("*").eq("email", email)'] },
  "C-SQL-DYNAMIC-EXEC": { file: "supabase/migrations/001.sql",
    hit: ["  execute 'select * from t where a = ''' || _v || '''';", "  return query execute 'select 1 from ' || _tabela;"],
    miss: ["  execute format('select * from t where a = %L', _v);", "  execute 'select * from t where a = $1' using _v || '%';", "  for each row execute function public.f();", "revoke execute on function public.f(text) from public;"] },
  "C-MATH-RANDOM": { file: "supabase/functions/x/index.ts",
    hit: ["const resetToken = Math.random().toString(36);", "const codigo = Math.floor(Math.random() * 1e6);"],
    miss: ["const cor = CORES[Math.floor(Math.random() * 4)];", "const token = crypto.randomUUID();"] },
  "C-STORAGE-SECRET": { file: "src/pages/Settings.tsx",
    hit: ['localStorage.setItem("gemini_api_key", key);', "sessionStorage.setItem('senha', s);"], miss: ['localStorage.setItem("theme", "dark");'] },
  "C-ERROR-LEAK": { file: "supabase/functions/x/index.ts",
    hit: ["return new Response(JSON.stringify({ error: error.message }), { status: 500 });", "return json(500, { erro: err.stack });"],
    miss: ['return jsonError(500, "Erro interno", cors, requestId);', "throw new Error(`falhou: ${error.message}`);", "console.error(error.message);"] },
  "C-LOG-SENSITIVE": { file: "supabase/functions/x/index.ts",
    hit: ["console.log('key', apiKey);", "console.log(req.headers);", "console.error(`falhou com ${userToken}`);", "console.log({ password });"],
    miss: ["console.log('pedido recebido', requestId);", "console.log('Token expirado, renovando');", 'console.error("senha incorreta para", userId);'] },
  "C-LIMIT-FROM-CLIENT": { file: "supabase/functions/x/index.ts",
    hit: ['.limit(Number(url.searchParams.get("limit")))', ".limit(body.limit)"], miss: [".limit(Math.min(pedido, 100))", ".limit(50)"] },
  "C-EMPTY-CATCH": { file: "src/x.ts",
    hit: ["try { a(); } catch {}", "} catch (e) { }"], miss: ["} catch (e) { log(e); }", "} catch { /* o log não pode derrubar a resposta */ }"] },
};

Deno.test("regras de linha: toda regra tem caso de teste", () => {
  assertEquals(LINE_RULES.map((r) => r.rule).sort(), Object.keys(CASOS).sort());
});

for (const rule of LINE_RULES) {
  const caso = CASOS[rule.rule];
  if (!caso) continue;
  Deno.test(`regra ${rule.rule}: dispara no padrão inseguro e se cala no seguro`, () => {
    for (const l of caso.hit) assert(rule.match(l, caso.file) !== null, `deveria disparar: ${l}`);
    for (const l of caso.miss) assertEquals(rule.match(l, caso.file), null, `não deveria disparar: ${l}`);
  });
}

// ------------------------------------------------------------------ da suspeita à prova (explore/PROTOCOLO.md)
Deno.test({ name: "PROVA executável na cobaia: usuário comum se promove a admin e se dá créditos", ...db, fn: async () => {
  const lab = await openProject(COBAIA);
  try {
    const ana = await lab.createUser("ana@exemplo.com");
    await lab.db.query("insert into profiles (user_id, display_name) values ($1, 'Ana')", [ana]);
    const r = await lab.as({ role: "authenticated", sub: ana },
      () => lab.db.query<{ role: string; credits: number }>("update profiles set role = 'admin', credits = 999999 returning role, credits"));
    assertEquals(r.rows[0], { role: "admin", credits: 999999 }); // S22/S23 deixam de ser suspeita
  } finally { await lab.close(); }
} });

Deno.test({ name: "PROVA executável na cobaia: visitante sem login lê e altera pagamentos; logado lê comentários alheios", ...db, fn: async () => {
  const lab = await openProject(COBAIA);
  try {
    const ana = await lab.createUser("ana@exemplo.com"), bruno = await lab.createUser("bruno@exemplo.com");
    await lab.db.query("insert into payments (user_id, amount) values ($1, 5000)", [ana]);
    await lab.as({ role: "anon" }, async () => {
      assertEquals((await lab.db.query("select * from payments")).rows.length, 1);
      assertEquals((await lab.db.query("update payments set status = 'paid' returning id")).rows.length, 1);
    });
    const nota = (await lab.as({ role: "authenticated", sub: ana },
      () => lab.db.query<{ id: string }>("insert into notes (title) values ('privada') returning id"))).rows[0]!.id;
    await lab.as({ role: "authenticated", sub: ana }, () => lab.db.query("insert into comments (note_id, user_id, body) values ($1, $2, 'segredo')", [nota, ana]));
    await lab.as({ role: "authenticated", sub: bruno }, async () => {
      assertEquals((await lab.db.query("select body from comments")).rows.length, 1);   // lê o comentário de Ana
      assertEquals((await lab.db.query("select * from notes")).rows.length, 0);          // controle: a nota em si está protegida
      await lab.db.query("insert into comments (note_id, user_id, body) values ($1, $2, 'forjado em nome de Ana')", [nota, ana]);
    });
  } finally { await lab.close(); }
} });

export type { Finding };
