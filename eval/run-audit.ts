// Suíte de auditoria: mede se uma IA, seguindo os roteiros de caça, ENCONTRA as
// falhas plantadas na cobaia (lab/cobaia) — em especial as de lógica, que a
// varredura determinística não alcança.
//
//   deno run -A eval/run-audit.ts [--model sonnet] [--no-scan] [--keep] [--out relatorio.md]
//
// NÃO roda no CI: custa tokens e não é determinística. A pontuação é
// determinística e testada (eval/score.ts).
//
// A cobaia é copiada SEM o gabarito. O agente recebe o playbook (somente
// leitura, por --add-dir) e, por padrão, o relatório da varredura — como numa
// exploração real (checklists/audit.md, Etapa 0). Com --no-scan mede-se a caça pura.
//
// Como ler: "recall" é a fração das falhas plantadas que foram encontradas.
// "Extras" são achados fora do gabarito: podem ser falso positivo ou falha real
// que ninguém plantou — só leitura humana decide. Uma execução é uma amostra.
import { claudeBin, copyDir, parseArgs, PLAYBOOK_DIR, runClaude } from "./lib.ts";
import { parseFindings, type Planted, scoreAudit } from "./score.ts";
import { scanProject } from "../explore/scan.ts";
import { renderMarkdown } from "../explore/report.ts";

const args = parseArgs(Deno.args);
const model = args.get("model") ?? "sonnet";
const withScan = !args.has("no-scan");
const keep = args.has("keep");
const outFile = args.get("out");

const gabarito: { falhas: Planted[] } = JSON.parse(await Deno.readTextFile(`${PLAYBOOK_DIR}/lab/gabarito.json`));

const fixture = await Deno.makeTempDir({ prefix: "audit-cobaia-" });
await copyDir(`${PLAYBOOK_DIR}/lab/cobaia`, fixture); // só a cobaia: o gabarito fica de fora
if (withScan) {
  const scan = await scanProject(fixture);
  await Deno.writeTextFile(`${fixture}/relatorio-varredura.md`, renderMarkdown(scan).replaceAll(fixture, "."));
}

const prompt = `Explore a segurança deste projeto usando o security-playbook em ${PLAYBOOK_DIR}
(comece por SECURITY.md e siga checklists/audit.md).
${withScan ? "A varredura determinística já rodou: o resultado está em relatorio-varredura.md. Faça a triagem dos suspeitos e, principalmente, a caça do que a varredura NÃO vê." : "Não há relatório de varredura: faça a exploração completa."}
Siga os roteiros de explore/hunts/ um por vez e o protocolo explore/PROTOCOLO.md.
Você só pode LER o projeto (não há ambiente para executar): a prova aceitável aqui é o
rastro no código, com arquivo e linha.

Ao final, escreva o arquivo achados.json na raiz do projeto: um array JSON em que cada
item tem "titulo", "severidade", "estado" ("confirmado" ou "suspeito"), "classe" (uma de:
acesso, injecao, segredos, custo, logica, cripto, resiliencia, config), "arquivo" (caminho
relativo à raiz), "linha", "evidencia" e "correcao". Inclua TODOS os achados — os que
vieram da varredura e os que você encontrou.`;

console.log(`Suíte de auditoria — modelo ${model} — ${withScan ? "com" : "sem"} varredura prévia — CLI: ${claudeBin()}`);
const r = await runClaude([
  "-p", prompt,
  "--output-format", "json",
  "--permission-mode", "acceptEdits",
  "--allowedTools", "Read Write Glob Grep",
  "--add-dir", PLAYBOOK_DIR,
  "--model", model,
  "--append-system-prompt",
  "Sessão não-interativa: não faça perguntas. Conclua a exploração e escreva o arquivo achados.json com a ferramenta Write.",
], fixture);

if (r.missing) {
  console.error(`ERRO: ${r.stderr}`);
  await Deno.remove(fixture, { recursive: true });
  Deno.exit(127);
}

let raw: string | null = null;
try { raw = await Deno.readTextFile(`${fixture}/achados.json`); } catch { /* o agente não escreveu o arquivo */ }
const reported = parseFindings(raw ?? r.result);

const out: string[] = [`# Suíte de auditoria — ${new Date().toISOString().slice(0, 16)} — modelo: ${model} — ${withScan ? "com" : "sem"} varredura prévia`, ""];
let ok = false;
if (!reported) {
  out.push(`**Sem resultado pontuável:** o agente não produziu achados.json legível (exit ${r.code}).`, "", "```", r.stderr.slice(0, 400) || r.result.slice(0, 400), "```");
} else {
  const s = scoreAudit(gabarito.falhas, reported);
  const pct = (n: number, d: number) => d === 0 ? "—" : `${Math.round((n / d) * 100)}%`;
  ok = true;
  out.push(
    `- **Recall geral:** ${s.found.length}/${s.total} (${pct(s.found.length, s.total)})`,
    ...Object.entries(s.byDetector).map(([d, v]) =>
      `- **${d === "agente" ? "Falhas de lógica (só a caça alcança)" : "Falhas de padrão (a varredura já entrega)"}:** ${v.found}/${v.total} (${pct(v.found, v.total)})`),
    `- **Achados reportados:** ${reported.length} · **fora do gabarito (extras):** ${s.extras.length} · **sem arquivo (não pontuam):** ${s.invalid}`,
    `- **Tempo:** ${r.seconds}s${r.costUsd ? ` · **custo:** US$ ${r.costUsd.toFixed(2)}` : ""}`,
    "", "## Falhas de lógica",
    ...gabarito.falhas.filter((f) => f.detector === "agente").map((f) => `- ${s.found.includes(f.id) ? "✅" : "❌"} ${f.id} — ${f.descricao}`),
    "", "## Não encontradas (demais)",
    ...gabarito.falhas.filter((f) => f.detector !== "agente" && s.missed.includes(f.id)).map((f) => `- ${f.id} — ${f.descricao} (${f.arquivo ?? f.objeto})`),
    "", "## Extras — ler um por um: falso positivo, ou falha real que ninguém plantou?",
    ...s.extras.map((e) => `- [${e.severidade ?? "?"}/${e.estado ?? "?"}] ${e.arquivo}:${e.linha ?? "?"} — ${e.titulo ?? "(sem título)"}`),
  );
}
const text = out.join("\n") + "\n";
console.log(text);
if (outFile) await Deno.writeTextFile(outFile, text);
if (keep) console.log(`fixture mantido: ${fixture}`);
else await Deno.remove(fixture, { recursive: true });
Deno.exit(ok ? 0 : 1);
