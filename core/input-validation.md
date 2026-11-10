---
owasp: [A05]
last-review: 2026-11-10
sources:
  - https://cheatsheetseries.owasp.org/cheatsheets/Input_Validation_Cheat_Sheet.html
  - https://cheatsheetseries.owasp.org/cheatsheets/Injection_Prevention_Cheat_Sheet.html
---

# Validação de Input

> Todo dado que entra no sistema vindo de fora é hostil até ser validado. Consulte este módulo ao criar endpoints, formulários, uploads, webhooks ou qualquer ponto que receba dados externos — incluindo output de LLM.

## Regras

- **R1 — MUST** validar todo input externo na fronteira do sistema (handler/endpoint), antes de qualquer uso. Input externo inclui: body, query params, headers, path params, cookies, arquivos, webhooks, mensagens de fila e **output de modelos de IA** (ver `../stack/ai-llm-security.md` R2).
- **R2 — MUST** validar por schema com tipos estritos (zod ou equivalente). Quando o domínio é enumerável (status, papéis, categorias), usar allowlist (`z.enum`), nunca string livre.
- **R3 — NEVER** construir SQL, comandos de shell ou queries por concatenação/interpolação de strings com dados externos. Sempre queries parametrizadas ou a API do client (Supabase `.eq()`, RPC com parâmetros).
- **R4 — MUST** validar uploads em cinco pontos: tamanho máximo **E** extensão permitida **E** content-type coerente com a extensão **E** assinatura do conteúdo (os primeiros bytes — extensão e content-type vêm do cliente e mentem) **E** nome: nunca usar o nome enviado pelo cliente para gravar, gerar nome próprio (`crypto.randomUUID()`). SVG e HTML são documentos ativos (executam script): fora da allowlist, salvo decisão registrada.
- **R5 — NEVER** usar blocklist/regex de "caracteres perigosos" como defesa principal. Blocklists sempre têm bypass; a defesa é allowlist + parametrização + encoding na saída.
- **R6 — MUST** impor limite de tamanho em todo campo e em todo payload — o do payload **antes** do parse. Campo sem limite é vetor de DoS e de estouro de custo (ex.: texto de 10 MB indo para um LLM).
- **R8 — MUST** o schema **rejeita campo desconhecido** (`z.object(...).strict()` ou equivalente). Campo a mais aceito em silêncio é o caminho do mass assignment: `{"title": "x", "role": "admin"}` repassado inteiro para um update.
- **R7 — MUST** revalidar no servidor mesmo o que o frontend já validou. Validação de frontend é UX; a de servidor é segurança.

## Padrões prontos

### P1 — Schema zod na fronteira do endpoint

<!-- ilustrativo -->

```typescript
import { z } from "zod";

// Limites explícitos e centralizados — ajuste por domínio.
const LIMITS = { TITLE: 500, QUESTION: 10_000, TAG: 100, MAX_TAGS: 20 } as const;

const createArtifactSchema = z.object({
  title: z.string().min(1).max(LIMITS.TITLE),
  question: z.string().min(1).max(LIMITS.QUESTION),
  projectId: z.string().uuid(),
  kind: z.enum(["bdd", "test-plan", "checklist"]), // allowlist, não string livre
  tags: z.array(z.string().max(LIMITS.TAG)).max(LIMITS.MAX_TAGS).optional(),
}).strict(); // campo desconhecido = rejeitado (R8)

// No handler:
const body: unknown = await req.json();
const parsed = createArtifactSchema.safeParse(body);
if (!parsed.success) {
  // Genérico para o cliente; detalhe vai para o log do servidor.
  console.error("[create-artifact] validação falhou:", parsed.error.flatten());
  return jsonError(400, "Dados inválidos");
}
const input = parsed.data; // daqui pra frente, tipado e validado
```

### P2 — Query parametrizada (nunca concatenada)

<!-- ilustrativo -->
```typescript
// ✅ API do client — o valor nunca entra na string SQL
const { data } = await supabase
  .from("qa_artifacts")
  .select("id, title")
  .eq("project_id", input.projectId)
  .eq("user_id", user.id); // filtro de dono SEMPRE (ver core/authorization.md R3)

// ✅ RPC com parâmetros nomeados — o Postgres recebe o valor separado do SQL
const { data: rows } = await supabase.rpc("search_artifacts", {
  _query: input.question,
  _user_id: user.id,
});
```

<!-- ilustrativo -->
```sql
-- A função RPC usa o parâmetro, nunca EXECUTE com concatenação:
CREATE OR REPLACE FUNCTION search_artifacts(_query text, _user_id uuid)
RETURNS SETOF qa_artifacts
LANGUAGE sql STABLE
AS $$
  SELECT * FROM qa_artifacts
  WHERE user_id = _user_id
    AND title ILIKE '%' || _query || '%'  -- concatenar VALOR parametrizado é seguro;
  LIMIT 50;                               -- concatenar texto para virar SQL (EXECUTE) não é
$$;
```

### P3 — Validação de upload (tamanho, extensão, tipo declarado e CONTEÚDO)

<!-- kit: kit/web/upload.ts#validateUpload -->
```typescript
interface FileKind {
  mime: string;
  ext: readonly string[];
  /** Confere os primeiros bytes do arquivo. `file.type` e a extensão vêm do
   *  cliente e mentem; o conteúdo é o que será servido e processado. */
  sniff: (head: Uint8Array) => boolean;
}

const startsWith = (sig: number[]) => (head: Uint8Array) => sig.every((b, i) => head[i] === b);
// Texto: UTF-8 válido e sem bytes de controle (NUL etc.) — barra binário renomeado.
function looksLikeText(head: Uint8Array): boolean {
  try { new TextDecoder("utf-8", { fatal: true }).decode(head); } catch { return false; }
  return !head.some((b) => b < 0x09 || (b > 0x0d && b < 0x20));
}

export const FILE_KINDS = {
  pdf: { mime: "application/pdf", ext: ["pdf"], sniff: startsWith([0x25, 0x50, 0x44, 0x46, 0x2d]) }, // %PDF-
  png: { mime: "image/png", ext: ["png"], sniff: startsWith([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]) },
  jpeg: { mime: "image/jpeg", ext: ["jpg", "jpeg"], sniff: startsWith([0xff, 0xd8, 0xff]) },
  txt: { mime: "text/plain", ext: ["txt"], sniff: looksLikeText },
  md: { mime: "text/markdown", ext: ["md"], sniff: looksLikeText },
} as const satisfies Record<string, FileKind>;

export type UploadCheck =
  | { ok: true; kind: keyof typeof FILE_KINDS; storageName: string }
  | { ok: false; reason: string };

/** `head` = primeiros bytes do arquivo (≥ 16; para texto, quanto mais melhor).
 *  SVG e HTML ficam fora de propósito: são documentos ativos (executam script). */
export function validateUpload(
  file: { name: string; type: string; size: number },
  head: Uint8Array,
  opts: { allowed: ReadonlyArray<keyof typeof FILE_KINDS>; maxBytes: number },
): UploadCheck {
  if (!Number.isInteger(file.size) || file.size <= 0 || file.size > opts.maxBytes) {
    return { ok: false, reason: "tamanho fora do limite" };
  }
  const ext = file.name.toLowerCase().match(/\.([a-z0-9]{1,8})$/)?.[1];
  if (!ext) return { ok: false, reason: "arquivo sem extensão reconhecível" };

  const kind = opts.allowed.find((k) => (FILE_KINDS[k].ext as readonly string[]).includes(ext));
  if (!kind) return { ok: false, reason: "extensão não permitida" };

  const spec: FileKind = FILE_KINDS[kind];
  // charset em "text/plain; charset=utf-8" é aceitável; o tipo base tem de bater com a extensão
  if (file.type.split(";")[0]!.trim().toLowerCase() !== spec.mime) {
    return { ok: false, reason: "content-type não corresponde à extensão" };
  }
  if (head.length === 0 || !spec.sniff(head)) {
    return { ok: false, reason: "conteúdo não corresponde ao tipo declarado" };
  }
  // Nome do cliente NUNCA vai para o storage (path traversal, colisão, XSS em listagem).
  return { ok: true, kind, storageName: `${crypto.randomUUID()}.${spec.ext[0]}` };
}
```

### P4 — Schema sem dependência, rejeitando campo desconhecido

<!-- kit: kit/supabase/function-template/schema.ts#schema -->
```typescript
export interface CreateNote { title: string; content: string }

const LIMITS = { TITLE: 500, CONTENT: 50_000 } as const;
const ALLOWED_KEYS = new Set(["title", "content"]);

/** Devolve o input validado ou `null`. Rejeita campo a mais: `{"role":"admin"}`
 *  junto do payload não "passa batido" para a camada de baixo. */
export function parseCreateNote(body: unknown): CreateNote | null {
  if (typeof body !== "object" || body === null || Array.isArray(body)) return null;
  const rec = body as Record<string, unknown>;
  if (Object.keys(rec).some((k) => !ALLOWED_KEYS.has(k))) return null;
  const { title, content } = rec;
  if (typeof title !== "string" || typeof content !== "string") return null;
  const t = title.trim();
  if (t.length < 1 || t.length > LIMITS.TITLE || content.length > LIMITS.CONTENT) return null;
  return { title: t, content };
}
```

## Anti-padrões

```typescript
// ❌ NUNCA: SQL por template string — injection direta [viola R3]
const rows = await db.query(`SELECT * FROM users WHERE email = '${email}'`);
// email = "x' OR '1'='1" lê a tabela inteira.

// ❌ NUNCA: JSON.parse sem schema — o tipo é mentira [viola R1, R2]
const input = JSON.parse(rawBody) as CreateArtifactRequest;
// O cast não valida nada; campos extras/ausentes/errados passam direto.

// ❌ NUNCA: "sanitizar" com blocklist [viola R5]
const clean = userInput.replace(/['"<>;]/g, "");
// Bypass trivial (encoding, unicode); e quebra dados legítimos ("O'Brien").

// ❌ NUNCA: confiar no nome/tipo do arquivo do cliente [viola R4]
await storage.upload(`docs/${file.name}`, file);
// file.name = "../../config/.env" → path traversal; file.type é forjável.
```

## Checklist

- [ ] Todo input novo do diff passa por schema zod (ou equivalente) na fronteira?
- [ ] Enums/categorias usam allowlist (`z.enum`), não string livre?
- [ ] Nenhuma query construída por concatenação/template string?
- [ ] Uploads validados em tamanho, extensão, content-type coerente e assinatura do conteúdo?
- [ ] Nome de arquivo gravado é gerado pelo servidor?
- [ ] Todos os campos têm limite de tamanho explícito, e o payload tem teto antes do parse?
- [ ] Schema rejeita campo desconhecido?
- [ ] Output de LLM usado pelo código também passa por schema?
