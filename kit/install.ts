// Instala o kit num projeto: copia os arquivos e reescreve os imports para o
// layout de destino. Não sobrescreve nada que já exista (use --force para isso)
// e não cria migration sem pedir (--sql).
//
//   deno run --allow-read --allow-write kit/install.ts <projeto> [--sql] [--force]
//
// Stack suportada hoje: Supabase (Edge Functions em supabase/functions/_shared).
// Em outra stack JS/TS, os arquivos de kit/web/ são autocontidos: copie-os.

const KIT = new URL(".", import.meta.url).pathname.replace(/\/$/, "");

export interface InstallResult { written: string[]; skipped: string[] }

function rewriteImports(source: string): string {
  return source
    .replaceAll('"../../web/', '"../_shared/')
    .replaceAll('"../guards.ts"', '"../_shared/guards.ts"')
    .replaceAll('"@supabase/supabase-js"', '"jsr:@supabase/supabase-js@2"');
}

export async function installKit(
  projectDir: string,
  opts: { sql?: boolean; force?: boolean; now?: Date } = {},
): Promise<InstallResult> {
  const root = projectDir.replace(/\/+$/, "");
  const written: string[] = [], skipped: string[] = [];

  async function put(rel: string, content: string) {
    const dest = `${root}/${rel}`;
    if (!opts.force) {
      try { await Deno.stat(dest); skipped.push(rel); return; } catch { /* não existe: seguir */ }
    }
    await Deno.mkdir(dest.replace(/\/[^/]+$/, ""), { recursive: true });
    await Deno.writeTextFile(dest, content);
    written.push(rel);
  }

  // 1. Helpers universais + guardas → supabase/functions/_shared/
  for await (const e of Deno.readDir(`${KIT}/web`)) {
    if (!e.isFile || !e.name.endsWith(".ts")) continue;
    const content = await Deno.readTextFile(`${KIT}/web/${e.name}`);
    // safe-url é de frontend; os demais são de servidor
    await put(e.name === "safe-url.ts" ? "src/lib/security/safe-url.ts" : `supabase/functions/_shared/${e.name}`, content);
  }
  await put("supabase/functions/_shared/guards.ts", await Deno.readTextFile(`${KIT}/supabase/guards.ts`));

  // 2. Template de função — pasta com "_" na frente não é publicada como função
  for (const f of ["index.ts", "schema.ts"]) {
    await put(`supabase/functions/_template/${f}`, rewriteImports(await Deno.readTextFile(`${KIT}/supabase/function-template/${f}`)));
  }

  // 3. SQL como migrations — só com --sql: cria tabelas (profiles, rate_limits,
  //    audit_log, qa_notes) e pode colidir com o que o projeto já tem.
  if (opts.sql) {
    const stamp = (opts.now ?? new Date()).toISOString().replace(/\D/g, "").slice(0, 14);
    const files: string[] = [];
    for await (const e of Deno.readDir(`${KIT}/supabase/sql`)) if (e.name.endsWith(".sql")) files.push(e.name);
    for (const [i, f] of files.sort().entries()) {
      const seq = String(BigInt(stamp) + BigInt(i));
      await put(`supabase/migrations/${seq}_playbook_${f.replace(/^\d+_/, "")}`, await Deno.readTextFile(`${KIT}/supabase/sql/${f}`));
    }
  }
  return { written: written.sort(), skipped: skipped.sort() };
}

if (import.meta.main) {
  const target = Deno.args.find((a) => !a.startsWith("--"));
  if (!target) {
    console.error("uso: deno run --allow-read --allow-write kit/install.ts <projeto> [--sql] [--force]");
    Deno.exit(64);
  }
  const r = await installKit(target, { sql: Deno.args.includes("--sql"), force: Deno.args.includes("--force") });
  for (const f of r.written) console.log(`  + ${f}`);
  for (const f of r.skipped) console.log(`  = ${f} (já existia — mantido; use --force para substituir)`);
  console.log(`\n${r.written.length} arquivo(s) escritos, ${r.skipped.length} mantidos.`);
  console.log("Próximos passos: definir ALLOWED_ORIGINS nos secrets; cadastrar as ações em rate_limits; copiar _template para cada função nova.");
}
