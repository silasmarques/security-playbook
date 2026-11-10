// Tipos do explorador. Um ACHADO sempre diz o que foi observado (evidência),
// com que grau de certeza (status) e como consertar (fix + referência à norma).

export type Severity = "CRÍTICO" | "ALTO" | "MÉDIO" | "BAIXO";

/** confirmado = observado no artefato (catálogo do Postgres após aplicar as
 *               migrations, ou fato objetivo de arquivo). Não depende de interpretação.
 *  suspeito   = padrão de código que costuma ser falha, mas exige leitura do
 *               contexto para confirmar. Vai para triagem — não é veredito. */
export type Status = "confirmado" | "suspeito";

export interface Finding {
  rule: string;        // id estável da regra, ex.: "DB-RLS-OFF"
  severity: Severity;
  status: Status;
  title: string;
  file?: string;       // caminho relativo à raiz do projeto analisado
  line?: number;
  object?: string;     // objeto de banco, ex.: "public.payments"
  evidence: string;    // o que foi visto, literalmente
  why: string;         // o que o atacante ganha
  fix: string;         // a mudança concreta
  ref: string;         // regra da norma, ex.: "stack/supabase-rls.md R1"
  kit?: string;        // arquivo do kit que resolve
}

export interface Suppressed { rule: string; file: string; line: number; reason: string }

export interface Coverage {
  migrationsApplied: string[];
  migrationsOutOfOrder: string[];
  migrationsFailed: Array<{ file: string; error: string }>;
  filesScanned: number;
  dbAnalyzed: boolean;
  notes: string[];     // o que NÃO foi analisado e por quê
}

export interface Report {
  project: string;
  findings: Finding[];
  suppressed: Suppressed[];
  coverage: Coverage;
}

export const SEVERITY_ORDER: Record<Severity, number> = { "CRÍTICO": 0, "ALTO": 1, "MÉDIO": 2, "BAIXO": 3 };

export function sortFindings(list: Finding[]): Finding[] {
  return [...list].sort((a, b) =>
    SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity] ||
    (a.status === b.status ? 0 : a.status === "confirmado" ? -1 : 1) ||
    a.rule.localeCompare(b.rule) ||
    (a.file ?? a.object ?? "").localeCompare(b.file ?? b.object ?? "") ||
    (a.line ?? 0) - (b.line ?? 0));
}
