// Type-check dos blocos TypeScript/TSX da seção "Padrões prontos" dos módulos:
//   deno run --allow-read --allow-write --allow-run --allow-net --allow-env scripts/check-code-blocks.ts
//
// Por que só "Padrões prontos": Anti-padrões são código intencionalmente errado;
// Regras/Checklist não têm código. O critério do design v1 ("todo padrão compila")
// vira verificação executável aqui.
//
// Como: cada bloco vira um arquivo .ts/.tsx num diretório temporário. Imports
// jsr:/npm:/conhecidos são resolvidos de verdade (zod, dompurify etc. têm os tipos
// reais checados); imports relativos (_shared/ de outro módulo) e nomes de contexto
// viram stubs `any` gerados automaticamente. Fragmento com `return` de handler é
// envolvido numa função. Escape hatch: linha `<!-- ci:no-check -->` antes do fence.

const KNOWN_BARE: Record<string, string> = {
  "zod": "npm:zod@3",
  "dompurify": "npm:dompurify@3",
  "jwt-decode": "npm:jwt-decode@4",
};

interface Block {
  module: string;
  index: number;
  lang: string;
  skip: boolean;
  code: string;
}

async function collectBlocks(): Promise<Block[]> {
  const blocks: Block[] = [];
  for (const dir of ["core", "stack"]) {
    for await (const e of Deno.readDir(dir)) {
      if (!e.isFile || !e.name.endsWith(".md")) continue;
      const lines = (await Deno.readTextFile(`${dir}/${e.name}`)).split("\n");
      let section = "", inBlock = false, lang = "", skipNext = false, skip = false;
      let buf: string[] = [], idx = 0;
      for (const line of lines) {
        const h = line.match(/^##\s+(.*)/);
        if (h && !inBlock) section = h[1].trim();
        if (!inBlock && line.trim() === "<!-- ci:no-check -->") { skipNext = true; continue; }
        const fence = line.match(/^```(\w*)/);
        if (fence && !inBlock) { inBlock = true; lang = fence[1]; buf = []; skip = skipNext; skipNext = false; continue; }
        if (fence && inBlock) {
          inBlock = false;
          if ((lang === "typescript" || lang === "tsx") && section === "Padrões prontos") {
            blocks.push({ module: `${dir}/${e.name}`, index: ++idx, lang, skip, code: buf.join("\n") });
          }
          continue;
        }
        if (inBlock) buf.push(line);
        if (line.trim() !== "") skipNext = false;
      }
    }
  }
  return blocks;
}

// Import relativo/desconhecido → stub any (valor + tipo, cobre anotação e uso).
function stubDecl(name: string): string {
  return `declare const ${name}: any; type ${name} = any;`;
}

function rewriteImports(code: string): { code: string; stubs: Set<string> } {
  const stubs = new Set<string>();
  const out = code.replace(
    /^import\s+(?:type\s+)?(.+?)\s+from\s+"([^"]+)";?\s*$/gm,
    (full, bindings: string, spec: string) => {
      if (spec.startsWith("jsr:") || spec.startsWith("npm:") || KNOWN_BARE[spec]) return full;
      const named = bindings.match(/\{([^}]*)\}/);
      if (named) {
        for (const n of named[1].split(",")) {
          const name = n.split(" as ").pop()!.trim();
          if (name) stubs.add(name);
        }
      }
      const def = bindings.replace(/\{[^}]*\}/, "").replace(/,/g, "").replace(/^\*\s+as\s+/, "").trim();
      if (def) stubs.add(def);
      return `// [ci-stub] ${full.trim()}`;
    },
  );
  return { code: out, stubs };
}

// Fragmento com `return` fora de função: hoisted imports + corpo numa função.
function wrapFragment(code: string): string {
  const lines = code.split("\n");
  const imports = lines.filter((l) => /^import\s/.test(l));
  const body = lines.filter((l) => !/^import\s/.test(l)).map((l) => l.replace(/^export\s+/, ""));
  return [...imports, "const __ciFragment = async (): Promise<any> => {", ...body, "};"].join("\n");
}

const GLOBAL_DTS = `// stubs globais dos exemplos (harness de teste, DOM/JSX, Vite)
declare const test: any;
declare const expect: any;
declare const describe: any;
declare const beforeAll: any;
declare const vi: any;
interface ImportMeta { readonly env: any; }
// class + namespace mergem: React vale como valor (createElement do jsx: "react")
// e como namespace de tipos (React.ReactNode).
declare class React {
  static createElement: any;
  static Fragment: any;
}
declare namespace React { type ReactNode = any; }
declare namespace JSX {
  interface IntrinsicElements { [tag: string]: any; }
  interface Element {}
}
`;

const tmp = await Deno.makeTempDir({ prefix: "playbook-ci-" });
await Deno.writeTextFile(`${tmp}/__stubs.d.ts`, GLOBAL_DTS);
await Deno.writeTextFile(`${tmp}/deno.json`, JSON.stringify({
  imports: KNOWN_BARE,
  compilerOptions: {
    jsx: "react",
    lib: ["dom", "dom.iterable", "deno.ns", "esnext"],
    noImplicitAny: false,               // fragmentos didáticos usam contexto implícito
    useUnknownInCatchVariables: false,  // exemplos de catch não re-anotam `e`
  },
}, null, 2));

async function denoCheck(file: string): Promise<string[]> {
  const cmd = new Deno.Command(Deno.execPath(), {
    args: ["check", "--config", `${tmp}/deno.json`, file],
    stdout: "piped",
    stderr: "piped",
    env: { NO_COLOR: "1" },
  });
  const { code, stderr } = await cmd.output();
  if (code === 0) return [];
  return new TextDecoder().decode(stderr).split("\n")
    .filter((l) => /error|TS\d+/.test(l) && !l.startsWith("Check "));
}

const blocks = await collectBlocks();
const failures: Array<{ id: string; errors: string[] }> = [];
let checked = 0, skipped = 0;

for (const b of blocks) {
  const id = `${b.module} bloco ${b.index}`;
  if (b.skip) { skipped++; continue; }
  checked++;

  const { code: rewritten, stubs } = rewriteImports(b.code);
  let code = rewritten;
  let wrapped = false;
  let errors: string[] = [];

  for (let iter = 0; iter < 5; iter++) {
    const prelude = `/// <reference path="./__stubs.d.ts" />\n` +
      [...stubs].map(stubDecl).join("\n") + "\n";
    const file = `${tmp}/${b.module.replace(/[\/.]/g, "_")}-${b.index}.${b.lang === "tsx" ? "tsx" : "ts"}`;
    await Deno.writeTextFile(file, prelude + code);
    errors = await denoCheck(file);
    if (errors.length === 0) break;

    let progressed = false;
    for (const e of errors) {
      const missing = e.match(/Cannot find name '(\w+)'/) ??
        e.match(/shorthand property '(\w+)'/);
      if (missing && !stubs.has(missing[1])) { stubs.add(missing[1]); progressed = true; }
    }
    if (!wrapped && errors.some((e) => e.includes("TS1108"))) {
      code = wrapFragment(code);
      wrapped = true;
      progressed = true;
    }
    if (!progressed) break;
  }

  if (errors.length > 0) failures.push({ id, errors: errors.slice(0, 5) });
}

console.log(`check-code-blocks: ${checked} bloco(s) verificados, ${skipped} pulado(s) (ci:no-check).`);
if (failures.length) {
  console.error(`\n${failures.length} bloco(s) com erro de compilação:\n`);
  for (const f of failures) {
    console.error(`FALHA ${f.id}`);
    for (const e of f.errors) console.error(`   ${e.trim().slice(0, 200)}`);
  }
  Deno.exit(1);
}
console.log("Todos os Padrões prontos type-checkam.");
