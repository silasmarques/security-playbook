// Orquestra a exploração determinística de um projeto.
// Núcleo universal: código + configuração (qualquer projeto JS/TS).
// Adaptador: banco — hoje, Supabase/Postgres (explore/supabase/).
import { createAnalysisDb } from "./supabase/analysis-db.ts";
import { applyMigrations, buildLocator, runDbChecks } from "./supabase/db-checks.ts";
import { runCodeChecks } from "./code-checks.ts";
import { type Finding, type Report, sortFindings } from "./types.ts";

export async function scanProject(projectDir: string): Promise<Report> {
  const root = projectDir.replace(/\/+$/, "");
  const code = await runCodeChecks(root);
  const notes = [...code.notes];

  let dbFindings: Finding[] = [];
  let migrationsApplied: string[] = [], migrationsOutOfOrder: string[] = [];
  let migrationsFailed: Array<{ file: string; error: string }> = [];
  let dbAnalyzed = false;

  let hasSupabase = true;
  try { await Deno.stat(`${root}/supabase`); } catch { hasSupabase = false; }
  if (!hasSupabase) {
    // Núcleo universal (código + config) já rodou. Prova de banco depende de adaptador.
    notes.push("Projeto sem pasta supabase/: nenhum adaptador de banco se aplica, então o banco NÃO foi analisado. As regras de código e configuração valem para qualquer projeto JS/TS.");
    return {
      project: root, findings: sortFindings(code.findings), suppressed: code.suppressed,
      coverage: { migrationsApplied, migrationsOutOfOrder, migrationsFailed, filesScanned: code.filesScanned, dbAnalyzed, notes },
    };
  }
  const db = await createAnalysisDb();
  try {
    ({ migrationsApplied, migrationsOutOfOrder, migrationsFailed } = await applyMigrations(db, root));
    if (migrationsApplied.length === 0 && migrationsFailed.length === 0) {
      notes.push("Nenhuma migration em supabase/migrations: o banco NÃO foi analisado (RLS, policies, funções, views).");
    } else {
      dbFindings = await runDbChecks(db, await buildLocator(root, migrationsApplied));
      dbAnalyzed = true;
      if (migrationsOutOfOrder.length > 0) {
        notes.push(`${migrationsOutOfOrder.length} migration(s) só aplicaram FORA DA ORDEM dos nomes (dependem de objeto criado em arquivo de data posterior). O histórico não é reproduzível do zero, e o estado analisado pode diferir do banco real — conferir os achados de banco contra o projeto na Supabase.`);
      }
      if (migrationsFailed.length > 0) {
        notes.push("Análise de banco PARCIAL: há migrations que não aplicaram no Postgres de análise. Objetos criados nelas (e o que depende deles) não foram verificados.");
      }
      notes.push("O banco analisado é o resultado das migrations do repositório. Mudança feita direto no painel da Supabase não aparece aqui — conferir o banco real com os advisors da plataforma.");
    }
  } finally {
    await db.close();
  }

  return {
    project: root,
    findings: sortFindings([...dbFindings, ...code.findings]),
    suppressed: code.suppressed,
    coverage: { migrationsApplied, migrationsOutOfOrder, migrationsFailed, filesScanned: code.filesScanned, dbAnalyzed, notes },
  };
}
