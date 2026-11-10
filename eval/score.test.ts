import { assert, assertEquals, assertFalse } from "@std/assert";
import { parseFindings, type Planted, scoreAudit, scoreScenario, type Scenario } from "./score.ts";
import { stripComments } from "./lib.ts";
import { SCENARIOS } from "./scenarios.ts";

const S3 = SCENARIOS.find((s) => s.id === "S3")!;
const files = (o: Record<string, string>) => new Map(Object.entries(o));

Deno.test("adoção: comentário e reporte NÃO satisfazem um MUST (regressão: o stub passava)", () => {
  const stub = `
    export async function handler(url: string) {
      if (!url.startsWith("https://")) throw new Error("protocol must be https");
      // TODO: bloquear IPs privados — 127.0.0.1, 10.0.0.0/8, 169.254.169.254 (metadata), 192.168.x
      /* e também link-local e private ranges */
      return await fetch(url, { signal: AbortSignal.timeout(5000) });
    }`;
  const r = scoreScenario(S3, files({ "supabase/functions/fetch-url/index.ts": stub }),
    "Implementei bloqueio de IP privado e metadata 169.254.169.254, com redirect manual revalidado.");
  assertFalse(r.pass);
  assertEquals(r.must.find((m) => m.name.includes("IP privado"))?.ok, false);
});

Deno.test("adoção: implementação real passa — reimplementando ou importando o kit", () => {
  const real = `
    const BLOCKED = [["127.0.0.0", 8], ["10.0.0.0", 8], ["169.254.0.0", 16], ["192.168.0.0", 16]];
    export async function handler(raw: string) {
      const url = new URL(raw);
      if (url.protocol !== "https:" && url.protocol !== "http:") throw new Error("x");
      if (isBlockedV4(url.hostname)) throw new Error("x");
      return await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(5000) });
    }`;
  assert(scoreScenario(S3, files({ "a.ts": real }), "").pass);
  const viaKit = `import { safeFetch } from "../_shared/ssrf.ts";\nexport const handler = (u: string) => safeFetch(u, { timeoutMs: 5000 });`;
  assert(scoreScenario(S3, files({ "a.ts": viaKit }), "").pass);
});

Deno.test("adoção: nenhum arquivo gerado reprova cenário que tem MUST; controle negativo acusa cerimônia", () => {
  assertFalse(scoreScenario(S3, new Map(), "fiz tudo").pass);
  const s4 = SCENARIOS.find((s) => s.id === "S4")!;
  assert(scoreScenario(s4, files({ "data.ts": "export const f = (d: Date) => d.toLocaleDateString('pt-BR');" }), "").pass);
  assertFalse(scoreScenario(s4, files({ "data.ts": "// formata\nconst rateLimit = 1; export const f = (d: Date) => String(d);" }), "").pass);
});

Deno.test("stripComments: tira comentário, preserva URL em string", () => {
  const out = stripComments('const u = "https://exemplo.com/x"; // 169.254.169.254\n/* 10.0.0.1 */ const a = 1;\n-- 192.168.0.1\nselect 1;');
  assert(out.includes("https://exemplo.com/x"));
  for (const ip of ["169.254", "10.0.0.1", "192.168"]) assertFalse(out.includes(ip), ip);
});

// ---------------------------------------------------------------- auditoria
const GAB: Planted[] = [
  { id: "L01", detector: "agente", classe: "acesso", arquivo: "supabase/functions/get-document/index.ts", linha: 14, severidade: "CRÍTICO", descricao: "" },
  { id: "L02", detector: "agente", classe: "custo", arquivo: "supabase/functions/ai-summarize/index.ts", linha: 25, severidade: "ALTO", descricao: "" },
  { id: "L03", detector: "agente", classe: "injecao", arquivo: "supabase/functions/ai-summarize/index.ts", linha: 22, severidade: "ALTO", descricao: "" },
  { id: "S02", detector: "scan", classe: "acesso", arquivo: "supabase/migrations/001.sql", linha: 43, objeto: "public.payments", severidade: "CRÍTICO", descricao: "" },
];

Deno.test("auditoria: casa por arquivo + classe, ou por arquivo + linha próxima", () => {
  const r = scoreAudit(GAB, [
    { arquivo: "supabase/functions/get-document/index.ts", linha: 9, classe: "acesso" },           // L01: classe igual
    { arquivo: "./supabase/functions/ai-summarize/index.ts", linha: 23, classe: "prompt-injection" }, // L03: classe diferente, linha perto
    { arquivo: "supabase/migrations/001.sql", classe: "acesso" },                                   // S02: sem linha
  ]);
  assertEquals(r.found.sort(), ["L01", "L03", "S02"]);
  assertEquals(r.missed, ["L02"]);
  assertEquals(r.recall, 0.75);
  assertEquals(r.byDetector, { agente: { total: 3, found: 2 }, scan: { total: 1, found: 1 } });
});

Deno.test("auditoria: um achado não vale por duas falhas; despejar achados não infla o recall", () => {
  const um = scoreAudit(GAB, [{ arquivo: "supabase/functions/ai-summarize/index.ts", linha: 24, classe: "custo" }]);
  assertEquals(um.found, ["L02"]); // só uma das duas falhas do mesmo arquivo
  const lixo = scoreAudit(GAB, [
    { arquivo: "src/qualquer.ts", linha: 1, classe: "acesso" },
    { arquivo: "supabase/functions/get-document/index.ts", linha: 400, classe: "config" }, // arquivo certo, longe e de outra classe
    { classe: "acesso" }, { titulo: "sem arquivo" },
  ]);
  assertEquals(lixo.found, []);
  assertEquals(lixo.extras.length, 2);
  assertEquals(lixo.invalid, 2);
});

Deno.test("auditoria: relatório vazio dá recall 0, não erro", () => {
  const r = scoreAudit(GAB, []);
  assertEquals([r.recall, r.found.length, r.missed.length], [0, 0, 4]);
});

Deno.test("parseFindings: aceita arquivo JSON, bloco cercado e objeto { achados }", () => {
  assertEquals(parseFindings('[{"arquivo":"a.ts"}]')?.length, 1);
  assertEquals(parseFindings('texto\n```json\n[{"arquivo":"a.ts"},{"arquivo":"b.ts"}]\n```\nfim')?.length, 2);
  assertEquals(parseFindings('{"achados":[{"arquivo":"a.ts"}]}')?.length, 1);
  assertEquals(parseFindings("nenhum json aqui"), null);
});

Deno.test("cenários: ids únicos e todo cenário com MUST tem ao menos um padrão que exige código", () => {
  const ids = SCENARIOS.map((s: Scenario) => s.id);
  assertEquals(new Set(ids).size, ids.length);
  for (const s of SCENARIOS) for (const c of [...s.must, ...s.forbidden]) assert(c.pattern instanceof RegExp, `${s.id}: ${c.name}`);
});
