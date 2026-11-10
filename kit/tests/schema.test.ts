import { assertEquals } from "@std/assert";
import { parseCreateNote } from "../supabase/function-template/schema.ts";

Deno.test("schema: payload válido passa e sai normalizado", () => {
  assertEquals(parseCreateNote({ title: "  Minha nota ", content: "" }), { title: "Minha nota", content: "" });
});

const INVALIDOS: Array<[string, unknown]> = [
  ["null", null], ["undefined (body ilegível)", undefined], ["array", [{ title: "a", content: "b" }]], ["string", "a"],
  ["título ausente", { content: "x" }],
  ["título vazio", { title: "   ", content: "x" }],
  ["título acima do limite", { title: "t".repeat(501), content: "x" }],
  ["conteúdo acima do limite", { title: "t", content: "c".repeat(50_001) }],
  ["tipo errado (número)", { title: 12345, content: "x" }],
  ["objeto aninhado no lugar de texto", { title: { $ne: null }, content: "x" }],
  ["campo a mais (mass assignment)", { title: "t", content: "x", user_id: "outro" }],
  ["campo a mais (escalada)", { title: "t", content: "x", role: "admin" }],
  ["__proto__ como campo", JSON.parse('{"title":"t","content":"x","__proto__":{"admin":true}}')],
];
for (const [nome, valor] of INVALIDOS) {
  Deno.test(`schema: rejeita ${nome}`, () => assertEquals(parseCreateNote(valor), null));
}

Deno.test("schema: texto com 'cara de ataque' é DADO válido — a defesa é parametrização, não blocklist", () => {
  for (const s of ["'; DROP TABLE users; --", "<script>alert(1)</script>", "../../etc/passwd", "O'Brien"]) {
    assertEquals(parseCreateNote({ title: s, content: s }), { title: s, content: s });
  }
});
