// Bancada de PROVA: carrega as migrations de um projeto num Postgres real e
// deixa executar SQL como anon, como um usuário ou como o servidor. É com isto
// que um achado sai de "suspeito" para "confirmado" (explore/PROTOCOLO.md):
//
//   const lab = await openProject("../meu-projeto");
//   const ana = await lab.createUser("ana@exemplo.com");
//   const r = await lab.as({ role: "authenticated", sub: ana },
//     () => lab.db.query("update profiles set role = 'admin' returning role"));
//   // r.rows[0].role === "admin"  → escalada de privilégio CONFIRMADA
//
// Limite: é o banco descrito pelas migrations, com um dublê de auth/storage.
// Prova lógica de banco (RLS, GRANT, função). Não prova nada sobre a rede, o
// Auth real ou configuração feita no painel.
import { type Actor, as, createUser, expectDenied } from "../../kit/supabase/testing.ts";
import { createAnalysisDb } from "./analysis-db.ts";
import { applyMigrations } from "./db-checks.ts";

export type { Actor };

export async function openProject(projectDir: string) {
  const db = await createAnalysisDb();
  const migrations = await applyMigrations(db, projectDir.replace(/\/+$/, ""));
  return {
    db,
    migrations,
    createUser: (email: string) => createUser(db, email),
    as: <T>(actor: Actor, fn: () => Promise<T>) => as(db, actor, fn),
    /** Devolve a mensagem de erro; LANÇA se o banco deixar passar. */
    expectDenied: (sql: string, params: unknown[] = []) => expectDenied(db, sql, params),
    close: () => db.close(),
  };
}
