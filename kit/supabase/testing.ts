// Postgres real (PGlite, WASM) com o dublê de Supabase aplicado.
// Usado pelos testes de SQL do kit e pelo explorador (explore/).
import { PGlite } from "@electric-sql/pglite";

const here = new URL(".", import.meta.url);
export const SHIM_SQL = await Deno.readTextFile(new URL("supabase-shim.sql", here));

export async function createDb(): Promise<PGlite> {
  const db = new PGlite();
  await db.exec(SHIM_SQL);
  return db;
}

export async function applyKitSql(db: PGlite, ...files: string[]): Promise<void> {
  for (const f of files) {
    await db.exec(await Deno.readTextFile(new URL(`sql/${f}`, here)));
  }
}

export type Actor = { role: "authenticated"; sub: string } | { role: "anon" } | { role: "service_role" };

/** Executa `fn` como um papel do Supabase (com o JWT correspondente) e SEMPRE
 *  volta ao superusuário depois — inclusive se `fn` lançar. */
export async function as<T>(db: PGlite, actor: Actor, fn: () => Promise<T>): Promise<T> {
  const claims = actor.role === "authenticated" ? { sub: actor.sub, role: "authenticated" } : { role: actor.role };
  await db.query("select set_config('request.jwt.claims', $1, false)", [JSON.stringify(claims)]);
  await db.exec(`set role ${actor.role}`);
  try {
    return await fn();
  } finally {
    await db.exec("reset role");
    await db.query("select set_config('request.jwt.claims', '', false)");
  }
}

export async function createUser(db: PGlite, email: string): Promise<string> {
  const r = await db.query<{ id: string }>("insert into auth.users (email) values ($1) returning id", [email]);
  return r.rows[0]!.id;
}

/** Roda a query esperando que o banco NEGUE; devolve a mensagem de erro.
 *  Se a query passar, o teste falha — é o que faz o teste negativo poder falhar. */
export async function expectDenied(db: PGlite, sql: string, params: unknown[] = []): Promise<string> {
  try {
    await db.query(sql, params);
  } catch (e) {
    return (e as Error).message;
  }
  throw new Error(`esperava negação, mas a query passou: ${sql}`);
}
