// Peças comuns das suítes com IA. Funciona em macOS, Linux e Windows.

export const PLAYBOOK_DIR = new URL("..", import.meta.url).pathname
  .replace(/^\/([A-Za-z]:)/, "$1") // Windows: /C:/x → C:/x
  .replace(/\/$/, "");

/** Localiza o CLI: variável CLAUDE_BIN, instalação local conhecida, ou PATH. */
export function claudeBin(): string {
  const fromEnv = Deno.env.get("CLAUDE_BIN");
  if (fromEnv) return fromEnv;
  const home = Deno.env.get("HOME") ?? Deno.env.get("USERPROFILE") ?? "";
  const exe = Deno.build.os === "windows" ? "claude.exe" : "claude";
  for (const candidate of [`${home}/.local/bin/${exe}`, `${home}/.claude/local/${exe}`]) {
    try { Deno.statSync(candidate); return candidate; } catch { /* tentar o próximo */ }
  }
  return "claude";
}

export interface ClaudeRun { code: number; result: string; costUsd: number | null; seconds: number; stderr: string; missing: boolean }

export async function runClaude(args: string[], cwd: string): Promise<ClaudeRun> {
  const started = Date.now();
  let out: Deno.CommandOutput;
  try {
    out = await new Deno.Command(claudeBin(), { args, cwd, stdout: "piped", stderr: "piped" }).output();
  } catch (e) {
    if (e instanceof Deno.errors.NotFound) {
      return { code: 127, result: "", costUsd: null, seconds: 0, stderr: "CLI `claude` não encontrado (defina CLAUDE_BIN)", missing: true };
    }
    throw e;
  }
  const raw = new TextDecoder().decode(out.stdout);
  let result = raw, costUsd: number | null = null;
  try {
    const json = JSON.parse(raw);
    result = typeof json.result === "string" ? json.result : "";
    if (typeof json.total_cost_usd === "number") costUsd = json.total_cost_usd;
  } catch { /* saída não-JSON: fica o texto cru */ }
  return { code: out.code, result, costUsd, seconds: Math.round((Date.now() - started) / 1000), stderr: new TextDecoder().decode(out.stderr), missing: false };
}

const IGNORE_DIRS = new Set(["node_modules", "dist", "build"]);

/** Arquivos de projeto (sem dotfiles, sem CLAUDE.md) — o que o agente produziu ou o que será auditado. */
export async function collectFiles(dir: string, base = dir): Promise<Map<string, string>> {
  const files = new Map<string, string>();
  for await (const e of Deno.readDir(dir)) {
    if (e.name.startsWith(".") || IGNORE_DIRS.has(e.name)) continue;
    const p = `${dir}/${e.name}`;
    if (e.isDirectory) for (const [k, v] of await collectFiles(p, base)) files.set(k, v);
    else if (e.name !== "CLAUDE.md") files.set(p.slice(base.length + 1), await Deno.readTextFile(p));
  }
  return files;
}

export async function copyDir(from: string, to: string): Promise<void> {
  await Deno.mkdir(to, { recursive: true });
  for await (const e of Deno.readDir(from)) {
    if (e.isDirectory) await copyDir(`${from}/${e.name}`, `${to}/${e.name}`);
    else await Deno.copyFile(`${from}/${e.name}`, `${to}/${e.name}`);
  }
}

/** Remove comentários (// … , /* … *\/ , -- …). A rubrica julga CÓDIGO:
 *  um comentário dizendo "bloquear 169.254" não é um bloqueio. */
export function stripComments(source: string): string {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, " ")
    .replace(/(^|[^:"'`\\])\/\/[^\n]*/g, "$1")
    .replace(/(^|\s)--[^\n]*/g, "$1");
}

export function parseArgs(argv: string[]): Map<string, string> {
  const args = new Map<string, string>();
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    if (!a.startsWith("--")) continue;
    const next = argv[i + 1];
    args.set(a.slice(2), next === undefined || next.startsWith("--") ? "true" : next);
  }
  return args;
}
