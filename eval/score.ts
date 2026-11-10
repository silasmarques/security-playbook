// Pontuação determinística das suítes com IA. Sem rede, sem modelo: testável.
import { stripComments } from "./lib.ts";

// ---------------------------------------------------------------- adoção
export interface Check { name: string; pattern: RegExp; minCount?: number }
export interface Scenario {
  id: string; title: string; prompt: string;
  must: Check[];      // sobre o CÓDIGO gerado, sem comentários. Faltou → reprova.
  bonus: Check[];     // sobre código + reporte. Pontua, não reprova.
  forbidden: Check[]; // sobre o código. Apareceu → reprova (cerimônia indevida).
}

export function countMatches(c: Check, text: string): number {
  const flags = c.pattern.flags.includes("g") ? c.pattern.flags : c.pattern.flags + "g";
  return text.match(new RegExp(c.pattern.source, flags))?.length ?? 0;
}

export interface ScenarioScore { pass: boolean; must: Array<{ name: string; ok: boolean }>; bonus: Array<{ name: string; ok: boolean }>; forbidden: string[] }

export function scoreScenario(s: Scenario, files: Map<string, string>, reportText: string): ScenarioScore {
  // MUST e FORBIDDEN olham só o código, sem comentários: o agente dizer que fez
  // (no reporte ou num comentário) não conta como ter feito.
  const code = [...files.values()].map(stripComments).join("\n\n");
  const must = s.must.map((c) => ({ name: c.name, ok: countMatches(c, code) >= (c.minCount ?? 1) }));
  const bonus = s.bonus.map((c) => ({ name: c.name, ok: countMatches(c, `${code}\n\n${reportText}`) >= (c.minCount ?? 1) }));
  const forbidden = s.forbidden.filter((c) => countMatches(c, code) >= (c.minCount ?? 1)).map((c) => c.name);
  return { pass: files.size > 0 || s.must.length === 0 ? must.every((m) => m.ok) && forbidden.length === 0 : false, must, bonus, forbidden };
}

// ---------------------------------------------------------------- auditoria
export interface Planted { id: string; detector: string; classe: string; arquivo?: string; linha?: number; objeto?: string; severidade: string; descricao: string }
export interface Reported { titulo?: string; classe?: string; arquivo?: string; linha?: number; estado?: string; severidade?: string }

export interface AuditScore {
  total: number; found: string[]; missed: string[];
  recall: number;
  extras: Reported[];       // fora do gabarito: falso positivo OU falha real não plantada — exige leitura
  byDetector: Record<string, { total: number; found: number }>;
  invalid: number;          // achados sem arquivo/classe: não pontuam
}

const norm = (p: string) => p.replace(/\\/g, "/").replace(/^\.\//, "").toLowerCase();

/** Um achado casa com uma falha plantada se aponta o MESMO arquivo e (a mesma
 *  classe OU uma linha a até 12 de distância). Falha de banco sem linha casa
 *  por arquivo + classe. Cada achado casa com no máximo uma falha, e vice-versa. */
export function scoreAudit(planted: Planted[], reported: Reported[]): AuditScore {
  const valid = reported.filter((r) => typeof r.arquivo === "string" && r.arquivo.length > 0);
  const byDetector: AuditScore["byDetector"] = {};
  for (const p of planted) (byDetector[p.detector] ??= { total: 0, found: 0 }).total++;

  // Todos os pares possíveis (falha, achado) com a sua distância; depois casa
  // do par mais próximo para o mais distante. Assim a ORDEM do gabarito não
  // decide quem fica com um achado disputado por duas falhas do mesmo arquivo.
  const pairs: Array<{ p: number; r: number; distance: number }> = [];
  planted.forEach((p, pi) => {
    if (!p.arquivo) return; // sem arquivo no gabarito não há como casar com rigor
    valid.forEach((r, ri) => {
      if (norm(r.arquivo!) !== norm(p.arquivo!)) return;
      const near = p.linha !== undefined && typeof r.linha === "number" ? Math.abs(r.linha - p.linha) : Infinity;
      const sameClass = r.classe === p.classe;
      if (!sameClass && near > 12) return;
      pairs.push({ p: pi, r: ri, distance: (sameClass ? 0 : 100) + Math.min(near, 50) });
    });
  });
  pairs.sort((a, b) => a.distance - b.distance || a.p - b.p || a.r - b.r);

  const used = new Set<number>(), matched = new Set<number>();
  for (const pair of pairs) {
    if (used.has(pair.r) || matched.has(pair.p)) continue;
    used.add(pair.r);
    matched.add(pair.p);
  }
  const found: string[] = [], missed: string[] = [];
  planted.forEach((p, pi) => {
    if (matched.has(pi)) { found.push(p.id); byDetector[p.detector]!.found++; } else missed.push(p.id);
  });
  return {
    total: planted.length, found, missed,
    recall: planted.length === 0 ? 0 : found.length / planted.length,
    extras: valid.filter((_, i) => !used.has(i)),
    byDetector,
    invalid: reported.length - valid.length,
  };
}

/** Extrai o array de achados de `achados.json` ou de um bloco ```json do texto. */
export function parseFindings(text: string): Reported[] | null {
  const candidates = [text, ...[...text.matchAll(/```(?:json)?\s*([\s\S]*?)```/g)].map((m) => m[1]!)];
  for (const c of candidates) {
    try {
      const v = JSON.parse(c.trim());
      if (Array.isArray(v)) return v as Reported[];
      if (Array.isArray(v?.achados)) return v.achados as Reported[];
    } catch { /* próximo candidato */ }
  }
  return null;
}
