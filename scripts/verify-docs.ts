// Verificação determinística do playbook (roda no CI e localmente):
//   deno run --allow-read scripts/verify-docs.ts
//
// 1. Todo link relativo .md resolve para arquivo existente.
// 2. Frontmatter `owasp:` consistente com a matriz (owasp-mapping.md), nas duas
//    direções: módulo citado na linha A0x tem A0x nas tags E toda tag A0x do
//    módulo aparece na linha A0x da matriz.
// 3. Limites de tamanho: SECURITY.md ≤ 150 linhas; módulos ≤ 400.
// 4. Frontmatter de módulo tem `last-review` (data) e tags válidas (A01–A10).

const errors: string[] = [];
const decoder = new TextDecoder();

async function read(path: string): Promise<string> {
  return decoder.decode(await Deno.readFile(path));
}

async function* mdFiles(): AsyncGenerator<string> {
  yield "SECURITY.md";
  yield "README.md";
  yield "owasp-mapping.md";
  for (const dir of ["core", "stack", "checklists", "prompts"]) {
    for await (const e of Deno.readDir(dir)) {
      if (e.isFile && e.name.endsWith(".md")) yield `${dir}/${e.name}`;
    }
  }
}

// --- 1. links relativos ---
for await (const file of mdFiles()) {
  const text = await read(file);
  const dir = file.includes("/") ? file.slice(0, file.lastIndexOf("/")) : ".";
  for (const m of text.matchAll(/\]\(([^)#\s]+\.md)(?:#[^)]*)?\)/g)) {
    const target = m[1].startsWith("http") ? null : `${dir}/${m[1]}`;
    if (!target) continue;
    try {
      await Deno.stat(target);
    } catch {
      errors.push(`link quebrado: ${file} -> ${m[1]}`);
    }
  }
}

// --- 2. frontmatter ↔ matriz ---
const tagRe = /^owasp:\s*\[([^\]]*)\]/m;
const moduleTags = new Map<string, string[]>();
for (const dir of ["core", "stack"]) {
  for await (const e of Deno.readDir(dir)) {
    if (!e.isFile || !e.name.endsWith(".md")) continue;
    const path = `${dir}/${e.name}`;
    const text = await read(path);
    const m = text.match(tagRe);
    if (!m) { errors.push(`frontmatter sem owasp: ${path}`); continue; }
    const tags = m[1].split(",").map((t) => t.trim()).filter(Boolean);
    for (const t of tags) {
      if (!/^A(0[1-9]|10)$/.test(t)) errors.push(`tag inválida em ${path}: ${t}`);
    }
    moduleTags.set(path, tags);
    if (!/^last-review:\s*\d{4}-\d{2}-\d{2}/m.test(text)) {
      errors.push(`frontmatter sem last-review válido: ${path}`);
    }
  }
}

const matrix = await read("owasp-mapping.md");
const rowModules = new Map<string, Set<string>>();
for (const line of matrix.split("\n")) {
  const row = line.match(/^\|\s*(A(?:0[1-9]|10))\s*\|/);
  if (!row) continue;
  const cat = row[1];
  const mods = new Set<string>();
  for (const l of line.matchAll(/\]\(((?:core|stack)\/[^)#]+\.md)\)/g)) mods.add(l[1]);
  rowModules.set(cat, mods);
}
for (const [mod, tags] of moduleTags) {
  for (const tag of tags) {
    if (!rowModules.get(tag)?.has(mod)) {
      errors.push(`matriz: ${mod} tem tag ${tag} mas não aparece na linha ${tag}`);
    }
  }
}
for (const [cat, mods] of rowModules) {
  for (const mod of mods) {
    if (!moduleTags.get(mod)?.includes(cat)) {
      errors.push(`matriz: linha ${cat} cita ${mod}, que não tem a tag ${cat}`);
    }
  }
}

// --- 3. limites de tamanho ---
const secLines = (await read("SECURITY.md")).split("\n").length;
if (secLines > 150) errors.push(`SECURITY.md com ${secLines} linhas (limite ~150)`);
for (const mod of moduleTags.keys()) {
  const n = (await read(mod)).split("\n").length;
  if (n > 400) errors.push(`${mod} com ${n} linhas (limite ~400)`);
}

// --- resultado ---
if (errors.length) {
  console.error(`verify-docs: ${errors.length} problema(s)\n`);
  for (const e of errors) console.error(`  - ${e}`);
  Deno.exit(1);
}
console.log(`verify-docs OK: links íntegros, matriz consistente (${moduleTags.size} módulos), limites respeitados.`);
