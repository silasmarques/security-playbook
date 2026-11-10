// Postgres de análise: o dublê de Supabase + as extensões mais comuns em
// projetos reais. Extensão que não existe aqui (pg_net, pg_cron, vault…) faz a
// migration falhar — e a falha aparece na cobertura do relatório.
import { PGlite } from "@electric-sql/pglite";
import { vector } from "@electric-sql/pglite/vector";
import { uuid_ossp } from "@electric-sql/pglite/contrib/uuid_ossp";
import { pg_trgm } from "@electric-sql/pglite/contrib/pg_trgm";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { citext } from "@electric-sql/pglite/contrib/citext";
import { unaccent } from "@electric-sql/pglite/contrib/unaccent";
import { SHIM_SQL } from "../../kit/supabase/testing.ts";

export async function createAnalysisDb(): Promise<PGlite> {
  const db = new PGlite({ extensions: { vector, uuid_ossp, pg_trgm, pgcrypto, citext, unaccent } });
  await db.exec(SHIM_SQL);
  // Na Supabase as extensões moram no schema `extensions`, que está no search_path.
  await db.exec(`
    create extension if not exists "uuid-ossp" with schema extensions;
    create extension if not exists pgcrypto with schema extensions;
    create extension if not exists vector with schema extensions;
    create extension if not exists pg_trgm with schema extensions;
    create extension if not exists citext with schema extensions;
    create extension if not exists unaccent with schema extensions;
    set search_path = "$user", public, extensions;
  `);
  return db;
}
