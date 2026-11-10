// Verificação determinística da documentação (CI e local):
//   deno run --allow-read scripts/verify-docs.ts [--strict-dates]
//
// 1. Todo link relativo aponta para arquivo que existe.
// 2. Frontmatter dos módulos: tags OWASP válidas, `last-review`, `sources`.
// 3. Matriz OWASP ↔ tags dos módulos, nas duas direções; e inegociáveis ↔ matriz.
// 4. Toda referência cruzada "módulo Rn/Pn" aponta para regra/padrão que existe.
// 5. Em "Padrões prontos", todo bloco TS/SQL ou vem do kit testado (marcador
//    `kit:`) ou está declarado `ilustrativo` — nada fica no meio-termo.
// 6. Contagens anunciadas (README, SECURITY.md) batem com o que existe.
// 7. Limites de tamanho. Cadência de revisão: aviso; com --strict-dates, erro.

import { markdownFiles } from "./sync-snippets.ts";

const errors: string[] = [];
const warnings: string[] = [];
const strictDates = Deno.args.includes("--strict-dates");
const read = (p: string) => Deno.readTextFile(p);
const exists = async (p: string) => { try { await Deno.stat(p); return true; } catch { return false; } };

const files: string[] = [];
for await (const f of markdownFiles()) files.push(f);
const texts = new Map<string, string>();
for (const f of files) texts.set(f, await read(f));

/** Remove blocos de código: link ou referência dentro de exemplo não é da doc. */
const prose = (md: string) => md.replace(/```[\s\S]*?```/g, (b) => "\n".repeat(b.split("\n").length - 1));

// --- 1. links relativos ---
for (const [file, text] of texts) {
  const dir = file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : ".";
  for (const m of prose(text).matchAll(/\]\(([^)\s]+)\)/g)) {
    const target = m[1]!.split("#")[0]!;
    if (!target || /^(https?:|mailto:)/.test(target)) continue;
    if (!(await exists(`${dir}/${target}`))) errors.push(`link quebrado: ${file} -> ${m[1]}`);
  }
}

// --- 2. frontmatter dos módulos ---
interface Module { path: string; name: string; tags: string[]; rules: Set<string>; review: string | null }
const modules = new Map<string, Module>();
for (const dir of ["core", "stack"]) {
  for await (const e of Deno.readDir(dir)) {
    if (!e.isFile || !e.name.endsWith(".md")) continue;
    const path = `${dir}/${e.name}`;
    const text = texts.get(path)!;
    const fm = text.match(/^---\n([\s\S]*?)\n---/)?.[1] ?? "";
    const tagLine = fm.match(/^owasp:\s*\[([^\]]*)\]/m);
    if (!tagLine) errors.push(`frontmatter sem owasp: ${path}`);
    const tags = (tagLine?.[1] ?? "").split(",").map((t) => t.trim()).filter(Boolean);
    for (const t of tags) if (!/^A(0[1-9]|10)$/.test(t)) errors.push(`tag inválida em ${path}: ${t}`);
    const review = fm.match(/^last-review:\s*(\d{4}-\d{2}-\d{2})\s*$/m)?.[1] ?? null;
    if (!review) errors.push(`frontmatter sem last-review válido: ${path}`);
    if (!/^sources:\s*\n\s+-\s+https?:\/\//m.test(fm)) errors.push(`frontmatter sem sources: ${path}`);
    const rules = new Set<string>();
    for (const m of text.matchAll(/^- \*\*(R\d+) — /gm)) rules.add(m[1]!);
    for (const m of text.matchAll(/^### (P\d+) — /gm)) rules.add(m[1]!);
    modules.set(e.name.replace(/\.md$/, ""), { path, name: e.name.replace(/\.md$/, ""), tags, rules, review });
  }
}

// --- 3. matriz ↔ tags, inegociáveis ↔ matriz ---
const matrix = texts.get("owasp-mapping.md")!;
const rowModules = new Map<string, Set<string>>();
const rowRules = new Map<string, Set<string>>();
for (const line of matrix.split("\n")) {
  const row = line.match(/^\|\s*(A(?:0[1-9]|10))\s*\|/);
  if (!row) continue;
  const mods = new Set<string>();
  for (const l of line.matchAll(/\]\(((?:core|stack)\/[^)#]+\.md)\)/g)) mods.add(l[1]!);
  rowModules.set(row[1]!, mods);
  const cell = line.split("|")[4] ?? "";
  rowRules.set(row[1]!, new Set([...cell.matchAll(/#(\d+)/g)].map((m) => m[1]!)));
}
for (const mod of modules.values()) {
  for (const tag of mod.tags) {
    if (!rowModules.get(tag)?.has(mod.path)) errors.push(`matriz: ${mod.path} tem tag ${tag} mas não aparece na linha ${tag}`);
  }
}
for (const [cat, mods] of rowModules) {
  for (const path of mods) {
    const mod = [...modules.values()].find((m) => m.path === path);
    if (!mod?.tags.includes(cat)) errors.push(`matriz: linha ${cat} cita ${path}, que não tem a tag ${cat}`);
  }
}
const security = texts.get("SECURITY.md")!;
const bloco1 = security.slice(security.indexOf("## Bloco 1"), security.indexOf("## Bloco 2"));
if (bloco1.length === 0) errors.push("SECURITY.md: Bloco 1 não encontrado");
const nonNegotiables = [...bloco1.matchAll(/^(\d+)\. \*\*.*$/gm)];
for (const m of nonNegotiables) {
  const tags = [...m[0].matchAll(/\[(A(?:0[1-9]|10))\]/g)].map((t) => t[1]!);
  if (tags.length === 0) errors.push(`SECURITY.md: inegociável ${m[1]} sem tag OWASP`);
  for (const t of tags) {
    const cell = rowRules.get(t);
    if (cell && cell.size > 0 && !cell.has(m[1]!)) errors.push(`matriz: inegociável #${m[1]} tem tag ${t} mas não está na coluna Inegociáveis da linha ${t}`);
  }
}
for (const [cat, nums] of rowRules) {
  for (const n of nums) {
    const item = nonNegotiables.find((m) => m[1] === n);
    if (!item) errors.push(`matriz: linha ${cat} cita inegociável #${n}, que não existe`);
    else if (!item[0].includes(`[${cat}]`)) errors.push(`matriz: linha ${cat} cita inegociável #${n}, que não tem a tag ${cat}`);
  }
}

// --- 4. referências cruzadas "módulo Rn/Pn" ---
const names = [...modules.keys()].sort((a, b) => b.length - a.length).join("|");
const refRe = new RegExp(
  "(?<![\\w-])(?:\\[)?`?(?:\\.\\./)*(?:core/|stack/)?(" + names + ")(?:\\.md)?`?(?:\\]\\([^)]*\\))?\\s+((?:[RP]\\d+)(?:\\s*[/–-]\\s*[RP]?\\d+)*)",
  "g",
);
for (const [file, text] of texts) {
  for (const m of prose(text).matchAll(refRe)) {
    const mod = modules.get(m[1]!)!;
    let kind = "";
    for (const part of m[2]!.split(/\s*[/–-]\s*/)) {
      const id = /^[RP]/.test(part) ? part : kind + part; // "R1–5" → R1, R5
      kind = id[0]!;
      if (!mod.rules.has(id)) errors.push(`referência inexistente: ${file} cita ${mod.name} ${id}`);
    }
  }
}

// --- 5. disciplina dos "Padrões prontos" ---
for (const mod of modules.values()) {
  const lines = texts.get(mod.path)!.split("\n");
  let section = "", inBlock = false;
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const h = line.match(/^##\s+(.*)/);
    if (h && !inBlock) section = h[1]!.trim();
    const fence = line.match(/^```(\w*)/);
    if (!fence) continue;
    if (inBlock) { inBlock = false; continue; }
    inBlock = true;
    if (section !== "Padrões prontos" || !/^(typescript|tsx|ts|sql)$/.test(fence[1]!)) continue;
    let j = i - 1;
    while (j >= 0 && lines[j]!.trim() === "") j--;
    const prev = lines[j] ?? "";
    if (!/^<!--\s*kit:\s*\S+\s*-->$/.test(prev) && !/^<!--\s*ilustrativo\s*-->$/.test(prev)) {
      errors.push(`${mod.path}:${i + 1} bloco ${fence[1]} em "Padrões prontos" sem origem — ligue ao kit (<!-- kit: … -->) ou declare <!-- ilustrativo -->`);
    }
  }
}

// --- 6. contagens anunciadas ---
const counts = {
  core: [...modules.values()].filter((m) => m.path.startsWith("core/")).length,
  stack: [...modules.values()].filter((m) => m.path.startsWith("stack/")).length,
  rules: nonNegotiables.length,
};
function expectCount(file: string, re: RegExp, expected: number, what: string) {
  const all = [...texts.get(file)!.matchAll(re)];
  if (all.length === 0) errors.push(`${file}: não anuncia a contagem de ${what}`);
  for (const m of all) if (Number(m[1]) !== expected) errors.push(`${file}: anuncia ${m[1]} ${what}, mas existem ${expected}`);
}
expectCount("README.md", /(\d+) regras inegociáveis/g, counts.rules, "regras inegociáveis");
expectCount("README.md", /(\d+) módulos \[core\/\]/g, counts.core, "módulos core");
expectCount("README.md", /(\d+) de \[stack\/\]/g, counts.stack, "módulos stack");
expectCount("SECURITY.md", /(\d+) módulos em \[core\/\]/g, counts.core, "módulos core");
expectCount("SECURITY.md", /(\d+) em \[stack\/\]/g, counts.stack, "módulos stack");

// --- 7. tamanho e cadência de revisão ---
const secLines = security.split("\n").length;
if (secLines > 150) errors.push(`SECURITY.md com ${secLines} linhas (limite 150 — é o arquivo que sempre vai para o contexto)`);
const today = Date.now();
for (const mod of modules.values()) {
  const n = texts.get(mod.path)!.split("\n").length;
  if (n > 400) errors.push(`${mod.path} com ${n} linhas (limite 400)`);
  if (!mod.review) continue;
  const age = Math.floor((today - Date.parse(mod.review)) / 86_400_000);
  const limit = mod.path.startsWith("stack/") ? 120 : 400; // stack: trimestral (+30 de folga); core: anual
  if (age > limit) {
    (strictDates ? errors : warnings).push(`revisão vencida: ${mod.path} revisado há ${age} dias (limite ${limit})`);
  }
}

// --- resultado ---
for (const w of warnings) console.warn(`  aviso: ${w}`);
if (errors.length) {
  console.error(`verify-docs: ${errors.length} problema(s)\n`);
  for (const e of errors) console.error(`  - ${e}`);
  Deno.exit(1);
}
console.log(`verify-docs OK: ${files.length} arquivos, ${modules.size} módulos (${counts.core} core + ${counts.stack} stack), ${counts.rules} inegociáveis; links, matriz, referências, origem dos padrões e contagens conferidos.`);
