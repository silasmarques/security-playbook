// Checagens de banco: aplica as migrations do projeto num Postgres real
// (PGlite + dublê de Supabase) e lê o CATÁLOGO. O achado não vem de regex sobre
// o SQL — vem do estado em que o banco de fato ficou depois de todas as
// migrations, que é o que importa (uma migration posterior pode desfazer outra).
import type { PGlite } from "@electric-sql/pglite";
import type { Finding } from "../types.ts";

const CLIENT_ROLES = ["anon", "authenticated"] as const;

// Colunas cujo valor não deveria ser escolhido pelo próprio usuário.
const SENSITIVE_COLUMN = /^(role|roles|is_admin|admin|is_staff|is_superuser|permissions?|plan|tier|subscription(_status|_tier)?|credits?|balance|saldo|quota|blocked(_at)?|banned(_at)?|verified(_at)?|approved(_at)?)$/i;

export interface MigrationResult {
  migrationsApplied: string[];
  /** Só aplicaram numa passada posterior: dependem de objeto criado em arquivo de data MAIOR. */
  migrationsOutOfOrder: string[];
  migrationsFailed: Array<{ file: string; error: string }>;
}

export async function applyMigrations(db: PGlite, projectDir: string): Promise<MigrationResult> {
  const dir = `${projectDir}/supabase/migrations`;
  const files: string[] = [];
  try {
    for await (const e of Deno.readDir(dir)) if (e.isFile && e.name.endsWith(".sql")) files.push(e.name);
  } catch { /* sem pasta de migrations */ }
  files.sort();

  const applied: string[] = [], late: string[] = [];
  let pending = files.map((f) => ({ file: `supabase/migrations/${f}`, sql: "", error: "" }));
  for (const p of pending) p.sql = await Deno.readTextFile(`${projectDir}/${p.file}`);

  // Cada arquivo roda numa transação: ou entra inteiro, ou não deixa resto.
  // Históricos reais nem sempre são reproduzíveis na ordem dos nomes (schema
  // base criado no painel e exportado depois). Por isso há passadas extras —
  // e o que só entrou fora de ordem fica DECLARADO, não escondido.
  for (let pass = 0; pending.length > 0; pass++) {
    const still: typeof pending = [];
    for (const p of pending) {
      try {
        await db.exec("begin");
        await db.exec(p.sql);
        await db.exec("commit");
        (pass === 0 ? applied : late).push(p.file);
      } catch (e) {
        p.error = (e as Error).message.split("\n")[0] ?? "erro";
        try { await db.exec("rollback"); } catch { /* sem transação aberta */ }
        still.push(p);
      }
    }
    if (still.length === pending.length) break; // passada sem progresso: acabou
    pending = still;
  }
  return {
    migrationsApplied: [...applied, ...late].sort(),
    migrationsOutOfOrder: late.sort(),
    migrationsFailed: pending.map((p) => ({ file: p.file, error: p.error })),
  };
}

/** Localiza onde um objeto foi criado, para o achado apontar arquivo:linha. */
export async function buildLocator(projectDir: string, files: string[]) {
  const sources: Array<{ file: string; lines: string[] }> = [];
  for (const f of files) sources.push({ file: f, lines: (await Deno.readTextFile(`${projectDir}/${f}`)).split("\n") });
  return (kind: "table" | "policy" | "function" | "view", name: string): { file?: string; line?: number } => {
    const esc = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    const q = `(?:"${esc}"|${esc})`;
    const pattern = {
      table: new RegExp(`create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?(?:public\\.)?${q}(?![\\w"])`, "i"),
      policy: new RegExp(`create\\s+policy\\s+${q}(?![\\w"])`, "i"),
      function: new RegExp(`create\\s+(?:or\\s+replace\\s+)?function\\s+(?:public\\.)?${q}\\s*\\(`, "i"),
      view: new RegExp(`create\\s+(?:or\\s+replace\\s+)?view\\s+(?:public\\.)?${q}(?![\\w"])`, "i"),
    }[kind];
    let hit: { file?: string; line?: number } = {};
    for (const s of sources) {
      s.lines.forEach((l, i) => { if (pattern.test(l)) hit = { file: s.file, line: i + 1 }; }); // a ÚLTIMA definição vale
    }
    return hit;
  };
}

type Locate = Awaited<ReturnType<typeof buildLocator>>;

export async function runDbChecks(db: PGlite, locate: Locate): Promise<Finding[]> {
  const out: Finding[] = [];
  const q = async <T>(sql: string) => (await db.query<T>(sql)).rows;

  // ---------- tabelas ----------
  const tables = await q<{ oid: number; name: string; rls: boolean; anon_any: boolean; auth_any: boolean; policies: number }>(`
    select c.oid::int as oid, c.relname as name, c.relrowsecurity as rls,
      has_table_privilege('anon', c.oid, 'select,insert,update,delete') as anon_any,
      has_table_privilege('authenticated', c.oid, 'select,insert,update,delete') as auth_any,
      (select count(*)::int from pg_policy p where p.polrelid = c.oid) as policies
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind in ('r', 'p') order by c.relname`);

  for (const t of tables) {
    const exposed = t.anon_any || t.auth_any;
    if (!t.rls) {
      out.push({
        rule: "DB-RLS-OFF", status: "confirmado", severity: exposed ? "CRÍTICO" : "MÉDIO",
        title: `Tabela public.${t.name} sem RLS`, object: `public.${t.name}`, ...locate("table", t.name),
        evidence: `pg_class.relrowsecurity = false; grants a clientes: anon=${t.anon_any}, authenticated=${t.auth_any}`,
        why: exposed
          ? "Qualquer pessoa com a chave pública do projeto lê e altera todas as linhas pela API REST."
          : "Hoje sem grants a clientes, mas a única trava é o GRANT: um grant futuro expõe a tabela inteira.",
        fix: `alter table public.${t.name} enable row level security; + policies por operação (ou nenhuma policy e revoke dos grants, se for tabela só do servidor).`,
        ref: "stack/supabase-rls.md R1", kit: "kit/supabase/sql/04_owned_table_template.sql",
      });
    } else if (t.policies === 0 && exposed) {
      out.push({
        rule: "DB-RLS-NO-POLICY", status: "confirmado", severity: "BAIXO",
        title: `public.${t.name}: RLS ligada, nenhuma policy, grants a clientes ainda presentes`,
        object: `public.${t.name}`, ...locate("table", t.name),
        evidence: `0 policies; anon=${t.anon_any}, authenticated=${t.auth_any}`,
        why: "Hoje nega tudo, mas com uma trava só: a primeira policy permissiva criada por engano abre a tabela.",
        fix: `Se é tabela só do servidor: revoke all on public.${t.name} from anon, authenticated;`,
        ref: "stack/supabase-rls.md R10", kit: "kit/supabase/sql/02_rate_limit.sql",
      });
    }
  }

  // ---------- policies ----------
  const policies = await q<{ table: string; name: string; cmd: string; roles: string[]; qual: string | null; check: string | null; toid: number }>(`
    select c.relname as "table", p.polname as name,
      case p.polcmd when 'r' then 'SELECT' when 'a' then 'INSERT' when 'w' then 'UPDATE' when 'd' then 'DELETE' else 'ALL' end as cmd,
      case when p.polroles = '{0}' then array['public'] else array(select rolname::text from pg_roles where oid = any(p.polroles)) end as roles,
      pg_get_expr(p.polqual, p.polrelid) as qual, pg_get_expr(p.polwithcheck, p.polrelid) as "check", c.oid::int as toid
    from pg_policy p join pg_class c on c.oid = p.polrelid join pg_namespace n on n.oid = c.relnamespace
    where n.nspname in ('public', 'storage') order by c.relname, p.polname`);

  const noInitPlan: string[] = [], noPgTemp: string[] = [];
  for (const p of policies) {
    const forClients = p.roles.some((r) => r === "public" || r === "anon" || r === "authenticated");
    if (!forClients) continue;
    const where = { object: `public.${p.table} / policy "${p.name}"`, ...locate("policy", p.name) };
    const exprs = [p.qual, p.check].filter((e): e is string => e !== null);
    const write = p.cmd !== "SELECT";

    if ((p.qual === "true" && p.cmd !== "INSERT") || p.check === "true") {
      out.push({
        rule: "DB-POLICY-TRUE", status: "confirmado", severity: write ? "CRÍTICO" : "ALTO", ...where,
        title: `Policy ${p.cmd} sem condição em ${p.table} (${p.roles.join(", ")})`,
        evidence: `${p.cmd} to ${p.roles.join(", ")}: using (${p.qual ?? "—"}) with check (${p.check ?? "—"})`,
        why: write
          ? "Qualquer cliente desse papel altera ou cria linhas de qualquer usuário."
          : "Qualquer cliente desse papel lê todas as linhas. Só é aceitável para dado realmente público.",
        fix: "Trocar por condição de dono — (select auth.uid()) = user_id — ou, se o dado é público de propósito, registrar a exceção.",
        ref: "stack/supabase-rls.md R3", kit: "kit/supabase/sql/04_owned_table_template.sql",
      });
    }
    if (exprs.some((e) => /user_metadata/i.test(e))) {
      out.push({
        rule: "DB-POLICY-USER-METADATA", status: "confirmado", severity: "ALTO", ...where,
        title: `Policy decide acesso por user_metadata em ${p.table}`,
        evidence: exprs.find((e) => /user_metadata/i.test(e))!,
        why: "user_metadata é editável pelo próprio usuário (auth.updateUser): ele escreve o papel que quiser e a policy acredita.",
        fix: "Ler papel de app_metadata (só o servidor escreve) ou de uma tabela de papéis protegida por RLS.",
        ref: "stack/supabase-rls.md R11",
      });
    }
    if (exprs.some((e) => /auth\.(uid|jwt|role)\(\)/.test(e.replace(/SELECT\s+auth\.(uid|jwt|role)\(\)/gi, "")))) {
      noInitPlan.push(`${p.table}."${p.name}"`);
    }
    // coluna usada na policy sem índice liderado por ela
    if (p.qual && p.table !== "objects") {
      const cols = await q<{ col: string; indexed: boolean }>(`
        select a.attname as col,
          exists (select 1 from pg_index i where i.indrelid = a.attrelid and i.indkey[0] = a.attnum) as indexed
        from pg_attribute a where a.attrelid = ${p.toid} and a.attnum > 0 and not a.attisdropped`);
      const bare = p.qual.replace(/'[^']*'/g, "''");
      for (const c of cols) {
        if (!c.indexed && new RegExp(`(?<![\\w.])${c.col}(?![\\w(])`).test(bare) &&
            !out.some((f) => f.rule === "DB-POLICY-NO-INDEX" && f.object === `public.${p.table}.${c.col}`)) {
          out.push({
            rule: "DB-POLICY-NO-INDEX", status: "confirmado", severity: "MÉDIO",
            object: `public.${p.table}.${c.col}`, ...locate("table", p.table),
            title: `Coluna ${p.table}.${c.col} filtra policy e não tem índice`,
            evidence: `policy "${p.name}": using (${p.qual}); nenhum índice começa por ${c.col}`,
            why: "A policy roda em toda query da tabela: sem índice é varredura completa por request — fácil de transformar em negação de serviço.",
            fix: `create index on public.${p.table} (${c.col});`,
            ref: "stack/supabase-rls.md R5", kit: "kit/supabase/sql/04_owned_table_template.sql",
          });
        }
      }
    }
  }

  if (noInitPlan.length > 0) {
    const tables = [...new Set(noInitPlan.map((x) => x.split(".")[0]!))];
    out.push({
      rule: "DB-POLICY-NO-INITPLAN", status: "confirmado", severity: "BAIXO",
      object: `${noInitPlan.length} policy(ies) em ${tables.length} tabela(s)`,
      title: "Policies chamam auth.uid() por linha, sem (select …)",
      evidence: noInitPlan.slice(0, 12).join(", ") + (noInitPlan.length > 12 ? `, … (+${noInitPlan.length - 12})` : ""),
      why: "Sem (select auth.uid()), a função é reavaliada a cada linha candidata: custo de CPU que vira lentidão e, sob carga, indisponibilidade.",
      fix: "Envolver em subselect: (select auth.uid()) = user_id — vale também para auth.jwt() e funções auxiliares estáveis.",
      ref: "stack/supabase-rls.md R3", kit: "kit/supabase/sql/04_owned_table_template.sql",
    });
  }

  // ---------- escrita por coluna (mass assignment) ----------
  const updatable = await q<{ table: string; col: string }>(`
    select c.relname as "table", a.attname as col
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
      join pg_attribute a on a.attrelid = c.oid and a.attnum > 0 and not a.attisdropped
    where n.nspname = 'public' and c.relkind in ('r', 'p')
      and has_column_privilege('authenticated', c.oid, a.attnum, 'update')
      and c.relrowsecurity -- sem RLS já é DB-RLS-OFF (crítico): não repetir por coluna
      and exists (
        select 1 from pg_policy p where p.polrelid = c.oid and p.polcmd in ('w', '*')
          and (p.polroles = '{0}' or exists (select 1 from pg_roles r where r.oid = any(p.polroles) and r.rolname in ('authenticated', 'anon'))))
    order by 1, 2`);
  for (const u of updatable.filter((u) => SENSITIVE_COLUMN.test(u.col))) {
    out.push({
      rule: "DB-COLUMN-WRITABLE", status: "suspeito", severity: "ALTO",
      object: `public.${u.table}.${u.col}`, ...locate("table", u.table),
      title: `Usuário autenticado pode escrever em ${u.table}.${u.col}`,
      evidence: `has_column_privilege('authenticated', '${u.table}', '${u.col}', 'update') = true e há policy de UPDATE para clientes`,
      why: "A policy escolhe as LINHAS, não as colunas: quem pode editar o próprio registro pode, pela API REST, mudar também este campo (ex.: promover-se).",
      fix: `revoke update on public.${u.table} from authenticated; grant update (<colunas editáveis>) on public.${u.table} to authenticated;`,
      ref: "stack/supabase-rls.md R9", kit: "kit/supabase/sql/01_profiles_access.sql",
    });
  }

  // ---------- funções SECURITY DEFINER ----------
  const fns = await q<{ name: string; args: string; config: string[] | null; anon: boolean; auth: boolean; argnames: string[] | null }>(`
    select p.proname as name, pg_get_function_identity_arguments(p.oid) as args, p.proconfig as config,
      has_function_privilege('anon', p.oid, 'execute') as anon,
      has_function_privilege('authenticated', p.oid, 'execute') as auth, p.proargnames::text[] as argnames
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.prosecdef order by p.proname`);
  for (const f of fns) {
    const where = { object: `public.${f.name}(${f.args})`, ...locate("function", f.name) };
    const sp = f.config?.find((c) => c.startsWith("search_path="))?.slice("search_path=".length);
    if (sp === undefined) {
      out.push({
        rule: "DB-DEFINER-SEARCH-PATH", status: "confirmado", severity: "ALTO", ...where,
        title: `SECURITY DEFINER sem search_path fixo: ${f.name}`,
        evidence: `prosecdef = true; proconfig = ${JSON.stringify(f.config)}`,
        why: "A função roda com os privilégios do dono e resolve nomes pelo search_path de quem chama: um objeto homônimo em outro schema é executado com privilégio elevado.",
        fix: "set search_path = '' na definição e schema explícito em todo objeto do corpo.",
        ref: "stack/supabase-rls.md R7", kit: "kit/supabase/sql/01_profiles_access.sql",
      });
    } else if (sp !== '""' && sp !== "" && !/pg_temp\s*$/.test(sp)) {
      noPgTemp.push(`${f.name}(${f.args}) → ${sp}`);
    }
    if (f.anon) {
      out.push({
        rule: "DB-DEFINER-ANON-EXEC", status: "confirmado", severity: "MÉDIO", ...where,
        title: `anon pode executar função que ignora RLS: ${f.name}`,
        evidence: "has_function_privilege('anon', …, 'execute') = true",
        why: "Função nova nasce executável por todos. Sendo SECURITY DEFINER, qualquer visitante sem login a chama pela API e ela roda sem a RLS dele.",
        fix: `revoke execute on function public.${f.name}(${f.args}) from public, anon; grant execute … to authenticated;`,
        ref: "stack/supabase-rls.md R7", kit: "kit/supabase/sql/01_profiles_access.sql",
      });
    }
    const idArg = (f.argnames ?? []).find((a) => /^_?(p_)?(user_?id|uid|owner(_id)?|account_id)$/i.test(a));
    if (idArg && (f.anon || f.auth)) {
      out.push({
        rule: "DB-DEFINER-ID-PARAM", status: "suspeito", severity: "ALTO", ...where,
        title: `SECURITY DEFINER recebe a identidade por parâmetro: ${f.name}(${idArg})`,
        evidence: `argumento "${idArg}"; executável por clientes (anon=${f.anon}, authenticated=${f.auth})`,
        why: "Quem chama escolhe o id: age em nome de outro usuário, e a RLS não está lá para barrar.",
        fix: "Tirar o parâmetro e usar auth.uid() dentro da função; ou restringir o EXECUTE ao service_role.",
        ref: "stack/supabase-rls.md R7", kit: "kit/supabase/sql/02_rate_limit.sql",
      });
    }
  }

  if (noPgTemp.length > 0) {
    out.push({
      rule: "DB-DEFINER-PG-TEMP", status: "confirmado", severity: "BAIXO",
      object: `${noPgTemp.length} função(ões) SECURITY DEFINER`,
      title: "SECURITY DEFINER com search_path sem pg_temp no fim",
      evidence: noPgTemp.slice(0, 10).join("; ") + (noPgTemp.length > 10 ? `; … (+${noPgTemp.length - 10})` : ""),
      why: "Sem pg_temp listado por último, o schema temporário é consultado PRIMEIRO: uma tabela temporária homônima sequestra a consulta.",
      fix: "Preferir set search_path = '' com schema explícito no corpo; alternativa: acrescentar pg_temp como último item.",
      ref: "stack/supabase-rls.md R7", kit: "kit/supabase/sql/01_profiles_access.sql",
    });
  }

  // ---------- views ----------
  const views = await q<{ name: string; opts: string[] | null; exposed: boolean }>(`
    select c.relname as name, c.reloptions as opts,
      (has_table_privilege('anon', c.oid, 'select') or has_table_privilege('authenticated', c.oid, 'select')) as exposed
    from pg_class c join pg_namespace n on n.oid = c.relnamespace
    where n.nspname = 'public' and c.relkind = 'v' order by c.relname`);
  for (const v of views) {
    const invoker = v.opts?.some((o) => /^security_invoker=(true|on|1)$/i.test(o)) ?? false;
    if (!invoker && v.exposed) {
      out.push({
        rule: "DB-VIEW-NO-INVOKER", status: "confirmado", severity: "ALTO",
        object: `public.${v.name}`, ...locate("view", v.name),
        title: `View public.${v.name} ignora a RLS das tabelas de origem`,
        evidence: `reloptions = ${JSON.stringify(v.opts)}; clientes têm SELECT`,
        why: "View roda como o dono: devolve as linhas de todos os usuários mesmo com RLS correta nas tabelas.",
        fix: `create view public.${v.name} with (security_invoker = true) as …`,
        ref: "stack/supabase-rls.md R7",
      });
    }
  }

  // ---------- storage ----------
  for (const b of await q<{ id: string }>("select id from storage.buckets where public order by id")) {
    out.push({
      rule: "DB-BUCKET-PUBLIC", status: "suspeito", severity: "MÉDIO", object: `storage.buckets/${b.id}`,
      title: `Bucket público: ${b.id}`,
      evidence: "storage.buckets.public = true",
      why: "Todo arquivo do bucket é legível por URL, sem login e sem policy. Certo para logotipo; vazamento para documento de usuário.",
      fix: "Bucket privado + policy por pasta + URL assinada de vida curta.",
      ref: "stack/supabase-rls.md R6", kit: "kit/supabase/sql/05_storage_policies.sql",
    });
  }
  return out;
}
