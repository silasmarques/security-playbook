import type { Finding, Report } from "./types.ts";

const where = (f: Finding) =>
  [f.file ? `${f.file}${f.line ? `:${f.line}` : ""}` : null, f.object ?? null].filter(Boolean).join(" · ");

export function renderMarkdown(r: Report): string {
  const conf = r.findings.filter((f) => f.status === "confirmado");
  const susp = r.findings.filter((f) => f.status === "suspeito");
  const count = (list: Finding[]) =>
    (["CRÍTICO", "ALTO", "MÉDIO", "BAIXO"] as const).map((s) => `${list.filter((f) => f.severity === s).length} ${s}`).join(" · ");
  const out: string[] = [
    `# Exploração de segurança — ${r.project}`,
    "",
    `**Confirmados (${conf.length}):** ${count(conf)}`,
    `**Suspeitos, para triagem (${susp.length}):** ${count(susp)}`,
    "",
    "## Cobertura — o que foi e o que NÃO foi analisado",
    "",
    `- Arquivos de código analisados: ${r.coverage.filesScanned}`,
    `- Banco: ${r.coverage.dbAnalyzed ? `${r.coverage.migrationsApplied.length} migration(s) aplicada(s) num Postgres real; achados lidos do catálogo` : "NÃO analisado"}`,
    ...r.coverage.migrationsFailed.map((m) => `- ⚠️ Migration NÃO aplicada: \`${m.file}\` — ${m.error}`),
    ...r.coverage.notes.map((n) => `- ${n}`),
    "- Fora do alcance desta varredura: falhas de lógica (IDOR em função, ausência de rate limit, prompt injection, corrida). Para essas, seguir os roteiros de `explore/hunts/`.",
  ];
  const section = (title: string, list: Finding[], intro: string) => {
    if (list.length === 0) return;
    out.push("", `## ${title}`, "", intro);
    for (const f of list) {
      out.push(
        "", `### [${f.severity}] ${f.title}`,
        `- **Onde:** ${where(f) || "projeto"}`,
        `- **Evidência:** \`${f.evidence.replace(/`/g, "'")}\``,
        `- **Por que importa:** ${f.why}`,
        `- **Como corrigir:** ${f.fix}`,
        `- **Norma:** ${f.ref}${f.kit ? ` · **Pronto no kit:** ${f.kit}` : ""}`,
        `- **Regra:** ${f.rule}`,
      );
    }
  };
  section("Achados confirmados", conf, "Observados no artefato (catálogo do banco ou fato de arquivo). Não dependem de interpretação.");
  section("Suspeitos — exigem leitura do contexto", susp, "Padrões que costumam ser falha. Cada um precisa ser confirmado ou descartado na triagem (`explore/PROTOCOLO.md`).");
  if (r.suppressed.length > 0) {
    out.push("", "## Exceções registradas no código", "", "Achados silenciados por `playbook-ignore` — revisar se o motivo ainda vale.", "");
    for (const s of r.suppressed) out.push(`- \`${s.file}:${s.line}\` · ${s.rule} — ${s.reason}`);
  }
  return out.join("\n") + "\n";
}
