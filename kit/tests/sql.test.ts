// Testes do SQL do kit contra Postgres real (PGlite) com o dublê de Supabase.
// Cada teste negativo usa `expectDenied`, que FALHA se o banco deixar passar.
import { assert, assertEquals, assertMatch } from "@std/assert";
import type { PGlite } from "@electric-sql/pglite";
import { applyKitSql, as, createDb, createUser, expectDenied } from "../supabase/testing.ts";

interface World { db: PGlite; A: string; B: string }

async function world(...files: string[]): Promise<World> {
  const db = await createDb();
  await applyKitSql(db, ...files);
  return { db, A: await createUser(db, "ana@exemplo.com"), B: await createUser(db, "bruno@exemplo.com") };
}
const user = (sub: string) => ({ role: "authenticated", sub }) as const;
const ANON = { role: "anon" } as const;
const SERVICE = { role: "service_role" } as const;

function dbTest(name: string, files: string[], fn: (w: World) => Promise<void>) {
  Deno.test({
    name,
    sanitizeResources: false, // PGlite mantém handles do WASM
    sanitizeOps: false,
    fn: async () => {
      const w = await world(...files);
      try { await fn(w); } finally { await w.db.close(); }
    },
  });
}

// ---------------------------------------------------------------- tabela com dono
dbTest("qa_notes: A×B — B não lê, não edita e não apaga a nota de A", ["04_owned_table_template.sql"], async ({ db, A, B }) => {
  const id = await as(db, user(A), async () =>
    (await db.query<{ id: string }>("insert into qa_notes (title, content) values ('privada', 'x') returning id")).rows[0]!.id);

  // controle positivo: o dono enxerga (sem isso, "B não vê" passaria até com a tabela vazia)
  assertEquals(await as(db, user(A), async () => (await db.query("select id from qa_notes")).rows.length), 1);

  await as(db, user(B), async () => {
    assertEquals((await db.query("select * from qa_notes where id = $1", [id])).rows.length, 0);
    assertEquals((await db.query("update qa_notes set title = 'hack' where id = $1 returning id", [id])).rows.length, 0);
    assertEquals((await db.query("delete from qa_notes where id = $1 returning id", [id])).rows.length, 0);
  });

  // a nota continua intacta
  const row = (await db.query<{ title: string }>("select title from qa_notes where id = $1", [id])).rows[0];
  assertEquals(row?.title, "privada");
});

dbTest("qa_notes: B não cria nota em nome de A; A não transfere a nota para B", ["04_owned_table_template.sql"], async ({ db, A, B }) => {
  await as(db, user(B), async () => {
    assertMatch(await expectDenied(db, "insert into qa_notes (user_id, title, content) values ($1, 'plantada', 'x')", [A]), /row-level security/);
  });
  await as(db, user(A), async () => {
    await db.query("insert into qa_notes (title, content) values ('minha', 'x')");
    assertMatch(await expectDenied(db, "update qa_notes set user_id = $1", [B]), /row-level security/);
  });
});

dbTest("qa_notes: anon não lê nem escreve", ["04_owned_table_template.sql"], async ({ db, A }) => {
  await as(db, user(A), () => db.query("insert into qa_notes (title, content) values ('minha', 'x')"));
  await as(db, ANON, async () => {
    assertMatch(await expectDenied(db, "select * from qa_notes"), /permission denied/);
    assertMatch(await expectDenied(db, "insert into qa_notes (title, content) values ('x', 'x')"), /permission denied/);
  });
});

dbTest("qa_notes: limites de tamanho são do banco, não só do frontend", ["04_owned_table_template.sql"], async ({ db, A }) => {
  await as(db, user(A), async () => {
    assertMatch(await expectDenied(db, "insert into qa_notes (title, content) values ($1, 'x')", ["t".repeat(501)]), /check constraint/);
    assertMatch(await expectDenied(db, "insert into qa_notes (title, content) values ('t', $1)", ["c".repeat(50001)]), /check constraint/);
  });
});

dbTest("qa_notes: catálogo — RLS ligada, 4 policies, índice na coluna de dono", ["04_owned_table_template.sql"], async ({ db }) => {
  const rls = (await db.query<{ relrowsecurity: boolean }>("select relrowsecurity from pg_class where relname = 'qa_notes'")).rows[0];
  assertEquals(rls?.relrowsecurity, true);
  const cmds = (await db.query<{ cmd: string }>("select cmd from pg_policies where tablename = 'qa_notes' order by cmd")).rows.map((r) => r.cmd);
  assertEquals(cmds, ["DELETE", "INSERT", "SELECT", "UPDATE"]);
  const idx = (await db.query<{ indexdef: string }>("select indexdef from pg_indexes where tablename = 'qa_notes'")).rows.map((r) => r.indexdef);
  assert(idx.some((d) => /\(user_id\)/.test(d)));
});

// ---------------------------------------------------------------- perfil / coluna
dbTest("profiles: usuário edita o próprio nome, mas NÃO se promove nem muda de plano", ["01_profiles_access.sql"], async ({ db, A }) => {
  await db.query("insert into profiles (user_id, display_name) values ($1, 'Ana')", [A]);
  await as(db, user(A), async () => {
    assertEquals((await db.query("update profiles set display_name = 'Ana M.' returning user_id")).rows.length, 1);
    for (const sql of [
      "update profiles set role = 'admin'",
      "update profiles set plan = 'enterprise'",
      "update profiles set blocked_at = null",
      "update profiles set display_name = 'x', role = 'admin'",
    ]) assertMatch(await expectDenied(db, sql), /permission denied/, sql);
  });
  const p = (await db.query<{ role: string; plan: string }>("select role, plan from profiles where user_id = $1", [A])).rows[0];
  assertEquals(p, { role: "member", plan: "free" });
});

dbTest("profiles: usuário não cria nem apaga perfil; não vê nem edita o de outro", ["01_profiles_access.sql"], async ({ db, A, B }) => {
  await db.query("insert into profiles (user_id, display_name) values ($1, 'Ana'), ($2, 'Bruno')", [A, B]);
  await as(db, user(B), async () => {
    assertEquals((await db.query("select * from profiles")).rows.length, 1); // só o dele
    assertEquals((await db.query("update profiles set display_name = 'hack' where user_id = $1 returning user_id", [A])).rows.length, 0);
    assertMatch(await expectDenied(db, "delete from profiles where user_id = $1", [B]), /permission denied/);
    assertMatch(await expectDenied(db, "insert into profiles (user_id, display_name, role) values ($1, 'x', 'admin')", [B]), /permission denied/);
  });
});

Deno.test({
  name: "PROVA DO PROBLEMA: sem privilégio por coluna, RLS correta deixa o usuário virar admin",
  sanitizeResources: false, sanitizeOps: false,
  fn: async () => {
    const db = await createDb();
    try {
      const A = await createUser(db, "ana@exemplo.com");
      await db.exec(`
        create table public.perfis_ingenuos (user_id uuid primary key, role text not null default 'member');
        alter table public.perfis_ingenuos enable row level security;
        create policy p on public.perfis_ingenuos for update to authenticated
          using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
        create policy s on public.perfis_ingenuos for select to authenticated using ((select auth.uid()) = user_id);
      `);
      await db.query("insert into perfis_ingenuos (user_id) values ($1)", [A]);
      const r = await as(db, user(A), () => db.query<{ role: string }>("update perfis_ingenuos set role = 'admin' returning role"));
      assertEquals(r.rows[0]?.role, "admin"); // a policy está "certa" e a escalada passou
    } finally { await db.close(); }
  },
});

dbTest("check_user_access: ativo → true; bloqueado, sem perfil → false; anon não executa", ["01_profiles_access.sql"], async ({ db, A, B }) => {
  await db.query("insert into profiles (user_id, display_name) values ($1, 'Ana')", [A]);
  const call = async () => (await db.query<{ ok: boolean }>("select check_user_access() as ok")).rows[0]!.ok;
  assertEquals(await as(db, user(A), call), true);
  assertEquals(await as(db, user(B), call), false); // sem perfil
  await db.query("update profiles set blocked_at = now() where user_id = $1", [A]);
  assertEquals(await as(db, user(A), call), false); // bloqueado
  await as(db, ANON, async () => assertMatch(await expectDenied(db, "select check_user_access()"), /permission denied/));
});

// ---------------------------------------------------------------- rate limit
const RL = ["02_rate_limit.sql"];
const hit = async (db: PGlite, action = "ai-chat") =>
  (await db.query<{ ok: boolean }>("select check_and_increment($1) as ok", [action])).rows[0]!.ok;

dbTest("rate limit: N chamadas passam, a N+1 é negada; outro usuário tem cota própria", RL, async ({ db, A, B }) => {
  await db.query("insert into rate_limits values ('ai-chat', 3, 3600)");
  await as(db, user(A), async () => {
    assertEquals([await hit(db), await hit(db), await hit(db)], [true, true, true]);
    assertEquals(await hit(db), false);
    assertEquals(await hit(db), false);
  });
  assertEquals(await as(db, user(B), () => hit(db)), true);
});

dbTest("rate limit: janela nova zera a contagem", RL, async ({ db, A }) => {
  await db.query("insert into rate_limits values ('ai-chat', 1, 3600)");
  await as(db, user(A), async () => { assertEquals(await hit(db), true); assertEquals(await hit(db), false); });
  await db.query("update usage_counters set window_start = window_start - interval '2 hours'"); // simula o tempo passando
  assertEquals(await as(db, user(A), () => hit(db)), true);
});

dbTest("rate limit: usuário NÃO zera, não lê nem edita contadores; não mexe nas regras", RL, async ({ db, A }) => {
  await db.query("insert into rate_limits values ('ai-chat', 1, 3600)");
  await as(db, user(A), async () => {
    await hit(db);
    for (const sql of [
      "delete from usage_counters",
      "update usage_counters set count = 0",
      "select * from usage_counters",
      "insert into usage_counters values (gen_random_uuid(), 'ai-chat', now(), 0)",
      "update rate_limits set max_calls = 1000000",
      "insert into rate_limits values ('livre', 1000000, 1)",
      "select * from rate_limits",
    ]) assertMatch(await expectDenied(db, sql), /permission denied/, sql);
    assertEquals(await hit(db), false); // continua estourado
  });
});

dbTest("rate limit: ação sem regra é ERRO (não 'liberado'); anon não executa", RL, async ({ db, A }) => {
  await as(db, user(A), async () => assertMatch(await expectDenied(db, "select check_and_increment('acao-inexistente')"), /unknown rate limit action/));
  assertEquals((await db.query("select * from usage_counters")).rows.length, 0); // nenhuma linha criada
  await as(db, ANON, async () => assertMatch(await expectDenied(db, "select check_and_increment('ai-chat')"), /permission denied/));
});

dbTest("rate limit: chamada sem identidade no token é rejeitada", RL, async ({ db }) => {
  await db.query("insert into rate_limits values ('ai-chat', 3, 3600)");
  await db.query("select set_config('request.jwt.claims', '{}', false)");
  await db.exec("set role authenticated");
  try { assertMatch(await expectDenied(db, "select check_and_increment('ai-chat')"), /not authenticated/); }
  finally { await db.exec("reset role"); }
});

// ---------------------------------------------------------------- auditoria
const AUDIT = ["03_audit_log.sql"];
dbTest("audit_log: servidor grava; usuário e anon não leem nem gravam", AUDIT, async ({ db, A }) => {
  await as(db, SERVICE, () => db.query("insert into audit_log (user_id, action, resource) values ($1, 'role.change', 'profiles:1')", [A]));
  assertEquals((await db.query("select * from audit_log")).rows.length, 1);
  for (const actor of [user(A), ANON]) {
    await as(db, actor, async () => {
      assertMatch(await expectDenied(db, "select * from audit_log"), /permission denied/);
      assertMatch(await expectDenied(db, "insert into audit_log (user_id, action, resource) values ($1, 'forjada', 'x')", [A]), /permission denied/);
      assertMatch(await expectDenied(db, "delete from audit_log"), /permission denied/);
    });
  }
});

dbTest("audit_log: append-only até para o service_role", AUDIT, async ({ db, A }) => {
  await as(db, SERVICE, async () => {
    await db.query("insert into audit_log (user_id, action, resource) values ($1, 'artifact.delete', 'a:1')", [A]);
    assertMatch(await expectDenied(db, "update audit_log set action = 'nada.aconteceu'"), /append-only/);
    assertMatch(await expectDenied(db, "delete from audit_log"), /append-only/);
    assertMatch(await expectDenied(db, "truncate audit_log"), /permission denied/);
  });
  assertEquals((await db.query<{ action: string }>("select action from audit_log")).rows[0]?.action, "artifact.delete");
});

// ---------------------------------------------------------------- storage (dublê)
dbTest("storage: cada usuário só enxerga e escreve na própria pasta", ["05_storage_policies.sql"], async ({ db, A, B }) => {
  await as(db, user(A), async () => {
    await db.query("insert into storage.objects (bucket_id, name) values ('documents', $1)", [`${A}/contrato.pdf`]);
    assertMatch(await expectDenied(db, "insert into storage.objects (bucket_id, name) values ('documents', $1)", [`${B}/plantado.pdf`]), /row-level security/);
    assertMatch(await expectDenied(db, "insert into storage.objects (bucket_id, name) values ('documents', 'solto-na-raiz.pdf')"), /row-level security/);
    assertMatch(await expectDenied(db, "insert into storage.objects (bucket_id, name) values ('outro-bucket', $1)", [`${A}/x.pdf`]), /row-level security|foreign key/);
  });
  await as(db, user(B), async () => {
    assertEquals((await db.query("select * from storage.objects")).rows.length, 0);
    assertEquals((await db.query("delete from storage.objects returning id")).rows.length, 0);
    assertEquals((await db.query("update storage.objects set name = $1 returning id", [`${B}/roubado.pdf`])).rows.length, 0);
  });
  await as(db, ANON, async () => assertEquals((await db.query("select * from storage.objects")).rows.length, 0));
  assertEquals((await db.query("select * from storage.objects")).rows.length, 1);
});

// ---------------------------------------------------------------- funções: postura
dbTest("SECURITY DEFINER do kit: search_path fixo e anon sem EXECUTE", ["01_profiles_access.sql", "02_rate_limit.sql"], async ({ db }) => {
  const fns = (await db.query<{ proname: string; proconfig: string[] | null; anon: boolean; pub: boolean }>(`
    select p.proname, p.proconfig,
           has_function_privilege('anon', p.oid, 'execute') as anon,
           exists (select 1 from aclexplode(p.proacl) a where a.grantee = 0 and a.privilege_type = 'EXECUTE') as pub
    from pg_proc p join pg_namespace n on n.oid = p.pronamespace
    where n.nspname = 'public' and p.prosecdef`)).rows;
  assertEquals(fns.map((f) => f.proname).sort(), ["check_and_increment", "check_user_access"]);
  for (const f of fns) {
    assert(f.proconfig?.some((c) => c === 'search_path=""'), `${f.proname}: search_path = ${f.proconfig}`);
    assertEquals(f.anon, false, `${f.proname}: anon executa`);
    assertEquals(f.pub, false, `${f.proname}: PUBLIC executa`);
  }
});
