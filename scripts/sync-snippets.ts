// Mantém os blocos de código da documentação IDÊNTICOS ao código testado do kit.
//
//   deno run --allow-read --allow-write scripts/sync-snippets.ts          (reescreve os .md)
//   deno run --allow-read scripts/sync-snippets.ts --check               (CI: falha se divergir)
//
// No markdown, a linha imediatamente antes do bloco diz de onde ele vem:
//   <!-- kit: kit/web/ssrf.ts#validateOutboundUrl -->
// O trecho é o que está entre `#region nome` e `#endregion nome` no arquivo
// (sem `#nome`: o arquivo inteiro). Assim, o que a norma mostra é exatamente o
// que os testes exercitam — não uma cópia que pode envelhecer.

const MARKER = /^<!--\s*kit:\s*([\w./-]+)(?:#([\w-]+))?\s*-->\s*$/;

export function extractRegion(source: string, region: string | undefined, where: string): string {
  if (!region) return source.replace(/\n+$/, "");
  const lines = source.split("\n");
  const start = lines.findIndex((l) => new RegExp(`^\\s*(?://|--)\\s*#region\\s+${region}\\s*$`).test(l));
  const end = lines.findIndex((l) => new RegExp(`^\\s*(?://|--)\\s*#endregion\\s+${region}\\s*$`).test(l));
  if (start < 0 || end < 0 || end <= start) throw new Error(`região "${region}" não encontrada em ${where}`);
  return lines.slice(start + 1, end).join("\n").replace(/^\n+|\n+$/g, "");
}

export interface SyncResult { text: string; blocks: number; errors: string[] }

export function syncMarkdown(md: string, readFile: (path: string) => string, file: string): SyncResult {
  const lines = md.split("\n");
  const out: string[] = [];
  const errors: string[] = [];
  let blocks = 0;
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i]!.match(MARKER);
    out.push(lines[i]!);
    if (!m) continue;
    const open = lines[i + 1] ?? "";
    if (!/^```\w+\s*$/.test(open)) { errors.push(`${file}:${i + 1} marcador kit sem bloco de código logo abaixo`); continue; }
    let close = i + 2;
    while (close < lines.length && !/^```\s*$/.test(lines[close]!)) close++;
    if (close >= lines.length) { errors.push(`${file}:${i + 1} bloco de código não fechado`); continue; }
    let body: string;
    try {
      body = extractRegion(readFile(m[1]!), m[2], m[1]!);
    } catch (e) {
      errors.push(`${file}:${i + 1} ${(e as Error).message}`);
      continue;
    }
    out.push(open, body, "```");
    blocks++;
    i = close;
  }
  return { text: out.join("\n"), blocks, errors };
}

export async function* markdownFiles(root = "."): AsyncGenerator<string> {
  for (const f of ["SECURITY.md", "README.md", "owasp-mapping.md", "CHANGELOG.md", "CLAUDE.md"]) {
    try { await Deno.stat(`${root}/${f}`); yield f; } catch { /* opcional */ }
  }
  for (const dir of ["core", "stack", "checklists", "prompts", "explore", "explore/hunts", "kit", "lab", "templates"]) {
    try {
      for await (const e of Deno.readDir(`${root}/${dir}`)) if (e.isFile && e.name.endsWith(".md")) yield `${dir}/${e.name}`;
    } catch { /* pasta opcional */ }
  }
}

if (import.meta.main) {
  const check = Deno.args.includes("--check");
  const problems: string[] = [];
  let total = 0, changed = 0;
  for await (const file of markdownFiles()) {
    const md = await Deno.readTextFile(file);
    const r = syncMarkdown(md, (p) => Deno.readTextFileSync(p), file);
    problems.push(...r.errors);
    total += r.blocks;
    if (r.text !== md) {
      changed++;
      if (check) problems.push(`${file}: bloco(s) divergem do kit — rode \`deno task snippets:write\``);
      else await Deno.writeTextFile(file, r.text);
    }
  }
  if (problems.length) {
    console.error(`sync-snippets: ${problems.length} problema(s)\n`);
    for (const p of problems) console.error(`  - ${p}`);
    Deno.exit(1);
  }
  console.log(`sync-snippets OK: ${total} bloco(s) ligados ao kit${check ? ", todos idênticos ao código testado" : `, ${changed} arquivo(s) atualizados`}.`);
}
