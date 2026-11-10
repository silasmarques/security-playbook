import { assertEquals, assertThrows } from "@std/assert";
import { extractRegion, syncMarkdown } from "./sync-snippets.ts";

const SRC = ["// cabeçalho", "// #region soma", "export const soma = (a: number, b: number) => a + b;", "// #endregion soma", "-- #region tabela", "create table t ();", "-- #endregion tabela"].join("\n");
const read = (p: string) => { if (p === "kit/x.ts") return SRC; throw new Error(`arquivo não existe: ${p}`); };

Deno.test("extractRegion: pega só o miolo, em TS e em SQL", () => {
  assertEquals(extractRegion(SRC, "soma", "x"), "export const soma = (a: number, b: number) => a + b;");
  assertEquals(extractRegion(SRC, "tabela", "x"), "create table t ();");
  assertThrows(() => extractRegion(SRC, "inexistente", "x"));
});

Deno.test("syncMarkdown: substitui o bloco pelo conteúdo do kit e é idempotente", () => {
  const md = ["texto", "<!-- kit: kit/x.ts#soma -->", "```typescript", "código VELHO e divergente", "```", "fim"].join("\n");
  const r = syncMarkdown(md, read, "m.md");
  assertEquals(r.errors, []);
  assertEquals(r.blocks, 1);
  assertEquals(r.text.split("\n")[3], "export const soma = (a: number, b: number) => a + b;");
  assertEquals(syncMarkdown(r.text, read, "m.md").text, r.text);
});

Deno.test("syncMarkdown: marcador quebrado é ERRO, não silêncio", () => {
  const casos = [
    "<!-- kit: kit/x.ts#nao-existe -->\n```ts\nx\n```",
    "<!-- kit: kit/nao-existe.ts -->\n```ts\nx\n```",
    "<!-- kit: kit/x.ts#soma -->\nparágrafo no lugar do bloco",
    "<!-- kit: kit/x.ts#soma -->\n```ts\nnunca fecha",
  ];
  for (const md of casos) assertEquals(syncMarkdown(md, read, "m.md").errors.length, 1, md);
});

Deno.test("syncMarkdown: bloco sem marcador fica intacto", () => {
  const md = "```ts\nconst a = 1;\n```";
  assertEquals(syncMarkdown(md, read, "m.md"), { text: md, blocks: 0, errors: [] });
});
