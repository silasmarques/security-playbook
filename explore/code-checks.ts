// Checagens de código e configuração: padrões que costumam ser falha.
// Quase tudo aqui sai como SUSPEITO — regex não entende contexto; quem
// confirma é a triagem (explore/PROTOCOLO.md). Sai CONFIRMADO só o que é fato
// objetivo de arquivo (ex.: não existe lockfile).
import type { Finding, Severity, Status, Suppressed } from "./types.ts";

type Zone = "functions" | "frontend" | "sql" | "other";

interface LineRule {
  rule: string; severity: Severity; status?: Status; zones?: Zone[];
  /** Devolve a evidência (trecho) se a linha casa; null caso contrário. */
  match: (line: string, file: string) => string | null;
  title: string; why: string; fix: string; ref: string; kit?: string;
}

const SKIP_DIRS = new Set(["node_modules", ".git", "dist", "build", ".next", ".vercel", ".claude", "coverage", ".turbo"]);
const CODE_EXT = /\.(ts|tsx|js|jsx|mjs|cjs|sql|toml|html)$/;
const TEST_FILE = /(\.|_)(test|spec)\.[a-z]+$|(^|\/)(__tests__|tests?|e2e)\//;
const MAX_BYTES = 500_000;

const re = (r: RegExp) => (line: string) => line.match(r)?.[0] ?? null;
/** Só o CÓDIGO de uma linha: apaga o texto de strings (mantendo as expressões
 *  `${…}` de templates). "Token expirado" numa mensagem não é um token no log. */
export function codeOnly(line: string): string {
  return line
    .replace(/`(?:[^`\\]|\\.)*`/g, (t) => (t.match(/\$\{[^}]*\}/g) ?? []).join(" "))
    .replace(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g, '""');
}
/** Nunca copiar um segredo inteiro para o relatório. */
const mask = (s: string) => s.length <= 10 ? s.slice(0, 3) + "…" : `${s.slice(0, 8)}…(${s.length} caracteres)`;

const SECRET_PATTERNS: RegExp[] = [
  /\bsk-[A-Za-z0-9_-]{20,}/,                               // chaves de API estilo OpenAI/Anthropic
  /\bAIza[0-9A-Za-z_-]{35}\b/,                             // Google API key
  /\beyJ[A-Za-z0-9_-]{15,}\.eyJ[A-Za-z0-9_-]{15,}\.[A-Za-z0-9_-]{10,}/, // JWT (ex.: service_role legado)
  /\bsb_secret_[A-Za-z0-9_-]{10,}/,                        // secret key nova da Supabase
  /\bgh[pousr]_[A-Za-z0-9]{36,}\b/,                        // token do GitHub
  /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/,
  /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/,                     // Stripe
];

const SECRET_NAME = /(KEY|SECRET|TOKEN|PASSWORD|SENHA|SALT|PRIVATE)/i;

export const LINE_RULES: LineRule[] = [
  {
    rule: "C-SECRET-HARDCODED", severity: "CRÍTICO",
    match: (l) => { for (const p of SECRET_PATTERNS) { const m = l.match(p); if (m) return mask(m[0]); } return null; },
    title: "Segredo no código",
    why: "Vai para o git e para todo clone, fork e log de CI. Considere a chave comprometida.",
    fix: "ROTACIONAR a chave agora; mover para o secret manager do ambiente e ler por nome.",
    ref: "core/secrets-config.md R1", kit: "kit/supabase/guards.ts",
  },
  {
    rule: "C-SECRET-IN-BUNDLE", severity: "CRÍTICO",
    match: (l, f) => l.match(/\bVITE_\w*(?:SERVICE_ROLE|SECRET|PRIVATE)\w*/)?.[0] ??
      (zoneOf(f) === "frontend" ? l.match(/\b(?:service_role|SERVICE_ROLE_KEY)\b|sb_secret_/)?.[0] ?? null : null),
    title: "Credencial administrativa exposta ao frontend",
    why: "Tudo com prefixo VITE_ (e tudo em src/) vai para o bundle público. A chave de serviço ignora RLS: é o banco inteiro aberto.",
    fix: "Tirar do frontend; a operação que precisa dela vira Edge Function.",
    ref: "core/secrets-config.md R3",
  },
  {
    rule: "C-CORS-WILDCARD", severity: "MÉDIO",
    match: re(/Access-Control-Allow-Origin["'`]?\s*[:,]\s*["'`]\*["'`]/i),
    title: "CORS aberto para qualquer origem",
    why: "Qualquer site chama o endpoint e lê a resposta. Com autenticação por cookie é crítico (o navegador envia a sessão sozinho); com Bearer o atacante ainda precisa do token, mas a allowlist deixa de ser uma camada.",
    fix: "Allowlist de origens vinda de env; origem fora da lista não recebe o header.",
    ref: "core/secrets-config.md R6", kit: "kit/web/cors.ts",
  },
  {
    rule: "C-ENV-FALLBACK", severity: "ALTO",
    match: (l) => {
      const m = l.match(/(?:Deno\.env\.get\(\s*["'`](\w+)["'`]\s*\)|process\.env\.(\w+)|import\.meta\.env\.(\w+))\s*(?:\?\?|\|\|)\s*["'`][^"'`]+["'`]/);
      return m && SECRET_NAME.test(m[1] ?? m[2] ?? m[3] ?? "") ? m[0].replace(/(["'`])[^"'`]+\1$/, "$1…$1") : null;
    },
    title: "Segredo com valor padrão no código",
    why: "Se a env faltar em produção, o sistema sobe em silêncio usando uma chave que está no repositório.",
    fix: "Sem fallback: ausente = falhar o boot.",
    ref: "core/secrets-config.md R8", kit: "kit/supabase/guards.ts",
  },
  {
    rule: "C-GETSESSION-SERVER", severity: "ALTO", zones: ["functions"],
    match: re(/\.auth\.getSession\s*\(/),
    title: "Decisão de servidor baseada em getSession()",
    why: "getSession() não valida o token com o servidor de auth: um JWT forjado ou revogado passa.",
    fix: "supabase.auth.getUser() (ou getClaims() com chave de assinatura assimétrica).",
    ref: "core/authentication.md R3", kit: "kit/supabase/function-template/index.ts",
  },
  {
    rule: "C-JWT-UNVERIFIED", severity: "ALTO", zones: ["functions"],
    // a CHAMADA (inclusive genérica: jwtDecode<T>(x)), não a linha do import
    match: re(/\bjwtDecode\s*(?:<[^\n(]*>)?\s*\(|\bjwt_decode\s*\(|atob\s*\([^)]*\.split\(\s*["']\.["']\s*\)/),
    title: "JWT decodificado sem verificar a assinatura",
    why: "O payload de um JWT é texto que qualquer um escreve. Sem verificar a assinatura, o atacante declara o papel que quiser.",
    fix: "Validar no servidor de auth (getUser) antes de confiar em qualquer claim.",
    ref: "core/authentication.md R2", kit: "kit/supabase/function-template/index.ts",
  },
  {
    rule: "C-IDENTITY-FROM-BODY", severity: "ALTO", zones: ["functions"],
    match: re(/\{[^}=]*\b(?:userId|user_id|uid|ownerId|owner_id)\b[^}=]*\}\s*=\s*(?:await\s+)?(?:req|request)\.json\(\)|\b(?:body|reqBody|requestBody)\.(?:userId|user_id|ownerId|owner_id)\b|searchParams\.get\(\s*["'](?:userId|user_id|uid|owner_id)["']\s*\)/),
    title: "Identidade do usuário lida do request",
    why: "Quem chama escolhe o id: lê e altera dados de qualquer usuário trocando um campo.",
    fix: "Identidade só de user.id, extraído do token verificado.",
    ref: "core/authentication.md R2", kit: "kit/supabase/function-template/index.ts",
  },
  {
    rule: "C-DANGEROUS-HTML", severity: "ALTO", zones: ["frontend"],
    match: (l, f) => /SafeHtml/i.test(f) ? null : re(/dangerouslySetInnerHTML|\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(/)(l),
    title: "HTML dinâmico inserido no DOM fora do wrapper sanitizado",
    why: "Se o conteúdo vem de usuário ou de LLM, é XSS: o script do atacante roda na sessão da vítima e leva o token.",
    fix: "Renderizar como texto; se HTML for necessário, só pelo componente SafeHtml (DOMPurify com allowlist).",
    ref: "core/frontend-security.md R1",
  },
  {
    rule: "C-REHYPE-RAW", severity: "ALTO", zones: ["frontend"],
    match: re(/rehypePlugins[^\n]*\brehypeRaw\b/), // o USO, não o import
    title: "Markdown com HTML cru habilitado",
    why: "Saída de LLM ou texto de usuário com <script>/<img onerror> é renderizada como HTML.",
    fix: "Remover rehypeRaw; se precisar de HTML, sanitizar com rehype-sanitize e allowlist.",
    ref: "core/frontend-security.md R7",
  },
  {
    rule: "C-OPEN-REDIRECT", severity: "ALTO", zones: ["frontend"],
    match: re(/(?:navigate|router\.(?:push|replace)|location\.(?:assign|replace))\s*\([^;\n]*searchParams\.get\(|(?:window\.)?location(?:\.href)?\s*=[^;\n]*searchParams\.get\(/),
    title: "Redirect para destino vindo da URL",
    why: "?next=https://site-falso leva a vítima a um phishing a partir do SEU domínio.",
    fix: "Aceitar só caminho interno, conferindo a origem depois de resolver a URL.",
    ref: "stack/react-typescript.md R7", kit: "kit/web/safe-url.ts",
  },
  {
    rule: "C-SQL-CONCAT", severity: "ALTO", zones: ["functions", "frontend", "other"],
    match: (l) => /\bsql\s*`/.test(l) ? null : re(/`\s*(?:select|insert\s+into|update|delete\s+from)\b[^`]*\$\{/i)(l),
    title: "SQL montado por interpolação de string",
    why: "Um valor com aspas vira parte do comando: leitura ou alteração de qualquer tabela.",
    fix: "API do client (.eq/.rpc) ou query parametrizada.",
    ref: "core/input-validation.md R3",
  },
  {
    rule: "C-SQL-DYNAMIC-EXEC", severity: "ALTO", zones: ["sql"],
    match: re(/\bexecute\b(?!\s+(?:format\s*\(|function\b|on\b))(?![^;]*\busing\b)[^;]*\|\|[^;]*/i), // format(%L) e USING são as formas seguras
    title: "EXECUTE com SQL concatenado dentro de função",
    why: "Injeção de SQL dentro do banco — e se a função é SECURITY DEFINER, com privilégio do dono.",
    fix: "execute format('… %L …', valor) ou execute … using valor; identificador só com %I.",
    ref: "core/input-validation.md R3",
  },
  {
    rule: "C-MATH-RANDOM", severity: "MÉDIO",
    match: (l) => /Math\.random\s*\(/.test(l) && /token|secret|c[oó]d(?:e|igo)|otp|senha|password|nonce|session|invite|convite|reset/i.test(l) ? "Math.random()" : null,
    title: "Math.random() gerando valor de segurança",
    why: "Não é criptograficamente seguro: a sequência é previsível a partir de poucas amostras.",
    fix: "crypto.getRandomValues / crypto.randomUUID.",
    ref: "core/crypto-data-protection.md R5", kit: "kit/web/crypto.ts",
  },
  {
    rule: "C-STORAGE-SECRET", severity: "MÉDIO", zones: ["frontend"],
    match: re(/(?:local|session)Storage\.setItem\(\s*["'`][^"'`]*(?:key|token|secret|senha|password)[^"'`]*["'`]/i),
    title: "Segredo digitado pelo usuário guardado no navegador",
    why: "Qualquer XSS futuro (ou extensão) lê o storage inteiro.",
    fix: "Enviar direto ao servidor para cifrar; não persistir no cliente.",
    ref: "stack/react-typescript.md R8",
  },
  {
    rule: "C-ERROR-LEAK", severity: "MÉDIO", zones: ["functions"],
    match: re(/(?:new\s+Response|\bjson|\bjsonError|\.send|\.json)\s*\([^\n]*\b(?:e|err|error|ex)\w*\.(?:message|stack)\b/),
    title: "Mensagem interna de erro devolvida ao cliente",
    why: "Erro de banco revela nome de tabela, coluna e constraint; stack revela caminhos e versões.",
    fix: "Resposta genérica + requestId; o detalhe vai só para o log.",
    ref: "core/error-handling-resilience.md R2", kit: "kit/web/error-boundary.ts",
  },
  {
    rule: "C-LOG-SENSITIVE", severity: "MÉDIO",
    match: (l) => {
      const call = l.match(/console\.(?:log|info|warn|error|debug)\s*\(.*/)?.[0];
      if (!call) return null;
      const m = codeOnly(call).match(/\b\w*(?:api_?key|token|password|senha|secret|authorization)\w*\b|\breq(?:uest)?\.headers\b/i);
      return m ? `console.…(${m[0]})` : null;
    },
    title: "Dado sensível indo para o log",
    why: "Log é lido por mais gente e guardado por mais tempo que o banco; token em log é token vazado.",
    fix: "Logger estruturado com redação por nome de chave.",
    ref: "core/logging-monitoring.md R2", kit: "kit/web/log.ts",
  },
  {
    rule: "C-LIMIT-FROM-CLIENT", severity: "MÉDIO", zones: ["functions"],
    match: re(/\.(?:limit|range)\s*\(\s*[^)\n]*(?:searchParams\.get|\bbody\.|\bquery\.|\bparams\.)/),
    title: "Volume da consulta controlado pelo cliente",
    why: "?limit=10000000 derruba o banco ou despeja a tabela inteira numa resposta.",
    fix: "Teto no servidor: Math.min(pedido, 100).",
    ref: "core/api-security.md R5",
  },
  {
    rule: "C-EMPTY-CATCH", severity: "BAIXO",
    match: re(/catch\s*(?:\([^)]*\))?\s*\{\s*\}/),
    title: "catch vazio",
    why: "Falha engolida em silêncio: se for numa checagem ou numa escrita, ninguém fica sabendo.",
    fix: "Logar e decidir explicitamente (propagar, negar ou degradar).",
    ref: "core/error-handling-resilience.md R3",
  },
];

export function zoneOf(file: string): Zone {
  if (file.endsWith(".sql")) return "sql";
  if (/(^|\/)supabase\/functions\//.test(file) || /(^|\/)(api|server|functions)\//.test(file)) return "functions";
  if (/(^|\/)(src|app|pages|components)\//.test(file) || /\.(tsx|jsx|html)$/.test(file)) return "frontend";
  return "other";
}

async function* walk(root: string, rel = ""): AsyncGenerator<string> {
  for await (const e of Deno.readDir(rel ? `${root}/${rel}` : root)) {
    const p = rel ? `${rel}/${e.name}` : e.name;
    if (e.isDirectory) { if (!SKIP_DIRS.has(e.name)) yield* walk(root, p); }
    else if (e.isFile) yield p;
  }
}

/** Argumentos de uma chamada a partir do "(" em `open`, respeitando aninhamento e strings. */
function callArgs(text: string, open: number): string {
  let depth = 0, quote = "";
  for (let i = open; i < Math.min(text.length, open + 2000); i++) {
    const ch = text[i]!;
    if (quote) { if (ch === "\\") i++; else if (ch === quote) quote = ""; continue; }
    if (ch === '"' || ch === "'" || ch === "`") { quote = ch; continue; }
    if (ch === "(") depth++;
    else if (ch === ")" && --depth === 0) return text.slice(open + 1, i);
  }
  return text.slice(open + 1, open + 400);
}

const FIXED_START = /^["'`]https?:\/\/[^$`"']+/;
const FROM_ENV = /Deno\.env\.get\(|process\.env\.|import\.meta\.env\.|mustGetEnv\(/;

/** O destino do fetch é fixo (não vem do request)? Vale: literal com host;
 *  CONSTANTE em maiúsculas; ou identificador definido, antes da chamada, a
 *  partir de literal com host, de env ou de outro destino fixo. Resolve até 3
 *  níveis; na dúvida responde "não" e o achado sai como suspeito. */
function fixedDestination(expr: string, before: string, depth = 0): boolean {
  const e = expr.trim();
  if (/^["'][^"']*["']$/.test(e) || FIXED_START.test(e) || FROM_ENV.test(e)) return true;
  const head = e.match(/^`\$\{\s*([\w.]+)\s*\}/)?.[1] ?? e.match(/^(?:new\s+URL\(\s*)?([A-Za-z_$][\w$]*)\s*(?:[,)+]|$|\.(?:toString|href))/)?.[1];
  if (!head) return false;
  if (/^[A-Z][A-Z0-9_]*$/.test(head)) return true;
  if (depth >= 3) return false;
  const name = head.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const defs = [...before.matchAll(new RegExp(`(?:const|let|var)\\s+${name}\\s*(?::[^=\\n]+)?=\\s*([^;\\n]+)`, "g"))];
  const last = defs.at(-1);
  return last ? fixedDestination(last[1]!, before.slice(0, last.index), depth + 1) : false;
}

function fetchFindings(file: string, text: string): Finding[] {
  if (zoneOf(file) !== "functions") return [];
  const out: Finding[] = [];
  const validated = /validateOutboundUrl|safeFetch/.test(text);
  for (const m of text.matchAll(/(?<![\w.$])fetch\s*\(/g)) {
    const args = callArgs(text, m.index + m[0].length - 1);
    const line = text.slice(0, m.index).split("\n").length;
    const first = args.split(/,(?![^({[]*[)}\]])/)[0]!.trim();
    if (!/\bsignal\b/.test(args)) {
      out.push({
        rule: "C-FETCH-NO-TIMEOUT", severity: "MÉDIO", status: "suspeito", file, line,
        title: "Chamada externa sem timeout", evidence: `fetch(${first.slice(0, 60)}…) sem signal`,
        why: "Se o destino travar, a função fica presa até o limite da plataforma: a lentidão do parceiro vira a sua indisponibilidade.",
        fix: "signal: AbortSignal.timeout(10_000) — ou usar fetchExternal/safeFetch do kit.",
        ref: "core/error-handling-resilience.md R4", kit: "kit/web/resilience.ts",
      });
    }
    if (!fixedDestination(first, text.slice(0, m.index)) && !validated) {
      out.push({
        rule: "C-FETCH-DYNAMIC-URL", severity: "ALTO", status: "suspeito", file, line,
        title: "fetch para URL dinâmica sem validação SSRF", evidence: `fetch(${first.slice(0, 80)})`,
        why: "Se a URL vem do usuário (ou de um LLM), o servidor é usado para alcançar a rede interna e o endpoint de metadata da nuvem.",
        fix: "safeFetch do kit: valida protocolo e faixa de IP, e revalida cada redirect.",
        ref: "core/authorization.md R6", kit: "kit/web/ssrf.ts",
      });
    }
  }
  return out;
}

async function exists(path: string): Promise<boolean> {
  try { await Deno.stat(path); return true; } catch { return false; }
}
async function readOpt(path: string): Promise<string | null> {
  try { return await Deno.readTextFile(path); } catch { return null; }
}

async function configFindings(root: string): Promise<Finding[]> {
  const out: Finding[] = [];
  const gitignore = await readOpt(`${root}/.gitignore`);
  if (gitignore === null || !/^\s*\.env(\b|\*|\.)/m.test(gitignore)) {
    out.push({
      rule: "CFG-GITIGNORE-ENV", severity: "ALTO", status: "confirmado", file: ".gitignore",
      title: ".env não está no .gitignore", evidence: gitignore === null ? ".gitignore ausente" : "nenhuma linha começa com .env",
      why: "O primeiro `git add .` com um .env na pasta publica todas as chaves do projeto.",
      fix: "Adicionar .env e .env.* (com !.env.example) antes do próximo commit.",
      ref: "core/secrets-config.md R1",
    });
  }
  if (await exists(`${root}/package.json`)) {
    const locks = ["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb", "deno.lock"];
    if (!(await Promise.all(locks.map((l) => exists(`${root}/${l}`)))).some(Boolean)) {
      out.push({
        rule: "CFG-NO-LOCKFILE", severity: "MÉDIO", status: "confirmado", file: "package.json",
        title: "Projeto sem lockfile", evidence: `nenhum de: ${locks.join(", ")}`,
        why: "Cada instalação resolve versões de novo: uma release comprometida de qualquer dependência entra sem ninguém aprovar.",
        fix: "Commitar o lockfile e instalar com `npm ci` no CI.",
        ref: "core/dependencies-supply-chain.md R1",
      });
    }
  }
  const tsconfigs: string[] = [];
  for await (const e of Deno.readDir(root)) if (e.isFile && /^tsconfig.*\.json$/.test(e.name)) tsconfigs.push(e.name);
  if (tsconfigs.length > 0) {
    const texts = await Promise.all(tsconfigs.map((f) => Deno.readTextFile(`${root}/${f}`)));
    if (!texts.some((t) => /"strict"\s*:\s*true/.test(t))) {
      out.push({
        rule: "CFG-TS-NOT-STRICT", severity: "BAIXO", status: "confirmado", file: tsconfigs.sort()[0]!,
        title: "TypeScript sem modo estrito", evidence: `"strict": true ausente em ${tsconfigs.sort().join(", ")}`,
        why: "null e any implícitos passam pelo compilador: o tipo diz uma coisa e o dado em produção é outra.",
        fix: `"strict": true (projeto legado: migração incremental registrada).`,
        ref: "stack/react-typescript.md R1",
      });
    }
  }
  const vercel = await readOpt(`${root}/vercel.json`);
  if (vercel !== null && !/Content-Security-Policy/i.test(vercel)) {
    out.push({
      rule: "CFG-NO-CSP", severity: "MÉDIO", status: "confirmado", file: "vercel.json",
      title: "Host sem Content-Security-Policy", evidence: "vercel.json não define o header",
      why: "Sem CSP, um XSS que passar tem liberdade total: carrega script de fora e envia dados para qualquer destino.",
      fix: "Headers de segurança no host, começando restrito.",
      ref: "core/frontend-security.md R3",
    });
  }
  const toml = await readOpt(`${root}/supabase/config.toml`);
  if (toml !== null) {
    let section = "";
    toml.split("\n").forEach((l, i) => {
      const s = l.match(/^\s*\[([^\]]+)\]/);
      if (s) section = s[1]!;
      if (/^\s*verify_jwt\s*=\s*false\b/.test(l)) {
        out.push({
          rule: "CFG-VERIFY-JWT-OFF", severity: "MÉDIO", status: "suspeito", file: "supabase/config.toml", line: i + 1,
          title: `Função sem verificação de JWT: ${section}`, evidence: `[${section}] verify_jwt = false`,
          why: "A função aceita chamada de qualquer pessoa na internet. Só é correto se ela mesma verifica outra prova (ex.: assinatura HMAC do webhook).",
          fix: "Conferir que a função valida assinatura + janela de tempo; senão, religar verify_jwt.",
          ref: "stack/edge-functions-deno.md R5", kit: "kit/web/crypto.ts",
        });
      }
    });
  }
  const wfDir = `${root}/.github/workflows`;
  if (await exists(wfDir)) {
    const names: string[] = [];
    for await (const e of Deno.readDir(wfDir)) if (e.isFile && /\.ya?ml$/.test(e.name)) names.push(e.name);
    for (const name of names.sort()) {
      const file = `.github/workflows/${name}`;
      const text = await Deno.readTextFile(`${wfDir}/${name}`);
      if (!/^permissions\s*:/m.test(text)) {
        out.push({
          rule: "CFG-WORKFLOW-PERMISSIONS", severity: "MÉDIO", status: "confirmado", file,
          title: "Workflow sem `permissions` mínimas", evidence: "nenhum bloco `permissions:` no nível do workflow",
          why: "O token do job herda o padrão do repositório, que pode ser de escrita: uma action comprometida altera código e releases.",
          fix: "permissions: { contents: read } no topo; ampliar só no job que precisa.",
          ref: "core/dependencies-supply-chain.md R7",
        });
      }
      const unpinned = [...text.matchAll(/^\s*-?\s*uses:\s*([\w.-]+\/[\w./-]+)@([^\s#]+)/gm)]
        .filter((m) => !/^[0-9a-f]{40}$/.test(m[2]!));
      if (unpinned.length > 0) {
        out.push({
          rule: "CFG-ACTION-UNPINNED", severity: "BAIXO", status: "confirmado", file,
          line: text.slice(0, unpinned[0]!.index).split("\n").length + (unpinned[0]![0].startsWith("\n") ? 1 : 0),
          title: "Action referenciada por tag, não por commit", evidence: unpinned.map((m) => `${m[1]}@${m[2]}`).join(", "),
          why: "Tag é móvel: quem compromete o repositório da action reaponta a tag e o seu CI roda o código dele com os seus secrets.",
          fix: "Fixar pelo SHA completo do commit, com a versão em comentário.",
          ref: "core/dependencies-supply-chain.md R10",
        });
      }
    }
  }
  return out;
}

export async function runCodeChecks(
  root: string,
): Promise<{ findings: Finding[]; suppressed: Suppressed[]; filesScanned: number; notes: string[] }> {
  const findings: Finding[] = [], suppressed: Suppressed[] = [], notes: string[] = [];
  let filesScanned = 0, skippedTests = 0, skippedBig = 0;

  for await (const file of walk(root)) {
    if (!CODE_EXT.test(file)) continue;
    if (TEST_FILE.test(file)) { skippedTests++; continue; }
    const stat = await Deno.stat(`${root}/${file}`);
    if (stat.size > MAX_BYTES) { skippedBig++; continue; }
    const text = await Deno.readTextFile(`${root}/${file}`);
    const lines = text.split("\n");
    const zone = zoneOf(file);
    filesScanned++;

    const candidates: Finding[] = [];
    lines.forEach((line, i) => {
      if (line.length > 2000) return; // linha minificada
      for (const r of LINE_RULES) {
        if (r.zones && !r.zones.includes(zone)) continue;
        if (!r.zones && zone === "sql") continue;
        const evidence = r.match(line, file);
        if (evidence === null) continue;
        candidates.push({
          rule: r.rule, severity: r.severity, status: r.status ?? "suspeito", file, line: i + 1,
          title: r.title, evidence: evidence.trim().slice(0, 160), why: r.why, fix: r.fix, ref: r.ref, kit: r.kit,
        });
      }
    });
    candidates.push(...fetchFindings(file, text));

    // Exceção registrada no ponto do código (SECURITY.md, Bloco 1):
    //   // playbook-ignore: C-CORS-WILDCARD endpoint público de status, sem dado de usuário
    for (const f of candidates) {
      const near = [lines[f.line! - 1] ?? "", lines[f.line! - 2] ?? ""].join("\n");
      const m = near.match(new RegExp(`playbook-ignore:\\s*${f.rule}\\s+(\\S.{9,})`));
      if (m) suppressed.push({ rule: f.rule, file, line: f.line!, reason: m[1]!.trim().replace(/\s*\*\/\s*$/, "") });
      else findings.push(f);
    }
  }
  findings.push(...await configFindings(root));
  if (skippedTests) notes.push(`${skippedTests} arquivo(s) de teste não analisados (segredos e vetores falsos são esperados neles).`);
  if (skippedBig) notes.push(`${skippedBig} arquivo(s) acima de ${MAX_BYTES / 1000} KB não analisados.`);
  notes.push("Arquivos .env* não são lidos: o explorador não copia segredos reais para relatórios. Use um secret scanner (gitleaks) para o histórico do git.");
  return { findings, suppressed, filesScanned, notes };
}
