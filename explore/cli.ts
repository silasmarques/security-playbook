// deno task explore <pasta-do-projeto> [--json arquivo] [--md arquivo] [--quiet]
// Saída: 0 = nada de CRÍTICO/ALTO confirmado e análise completa;
//        1 = há achado CRÍTICO/ALTO confirmado;
//        2 = análise incompleta (migration que não aplicou) — o resultado NÃO é um "limpo".
import { scanProject } from "./scan.ts";
import { renderMarkdown } from "./report.ts";

const args = [...Deno.args];
const take = (flag: string) => { const i = args.indexOf(flag); return i >= 0 ? args.splice(i, 2)[1] : undefined; };
const jsonOut = take("--json"), mdOut = take("--md");
const quiet = args.includes("--quiet");
const project = args.find((a) => !a.startsWith("--"));
if (!project) {
  console.error("uso: deno task explore <pasta-do-projeto> [--json arquivo] [--md arquivo] [--quiet]");
  Deno.exit(64);
}

const report = await scanProject(project);
const md = renderMarkdown(report);
if (jsonOut) await Deno.writeTextFile(jsonOut, JSON.stringify(report, null, 2));
if (mdOut) await Deno.writeTextFile(mdOut, md);
if (!quiet) console.log(md);

const incomplete = report.coverage.migrationsFailed.length > 0;
const serious = report.findings.some((f) => f.status === "confirmado" && (f.severity === "CRÍTICO" || f.severity === "ALTO"));
Deno.exit(incomplete ? 2 : serious ? 1 : 0);
