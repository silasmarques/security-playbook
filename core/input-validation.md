---
owasp: [A05]
last-review: 2026-06-11
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
- **R4 — MUST** validar uploads em quatro dimensões: extensão permitida **E** content-type **E** tamanho máximo **E** nome do arquivo. Nunca usar o nome enviado pelo cliente para gravar — gerar nome próprio (`crypto.randomUUID()`). Nome com `../` ou `\` é path traversal.
- **R5 — NEVER** usar blocklist/regex de "caracteres perigosos" como defesa principal. Blocklists sempre têm bypass; a defesa é allowlist + parametrização + encoding na saída.
- **R6 — MUST** impor limite de tamanho em todo campo e em todo payload. Campo sem limite é vetor de DoS e de estouro de custo (ex.: texto de 10 MB indo para um LLM).
- **R7 — MUST** revalidar no servidor mesmo o que o frontend já validou. Validação de frontend é UX; a de servidor é segurança.

## Padrões prontos

### P1 — Schema zod na fronteira do endpoint

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
});

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

```sql
-- A função RPC usa o parâmetro, nunca EXECUTE com concatenação:
CREATE OR REPLACE FUNCTION search_artifacts(_query text, _user_id uuid)
RETURNS SETOF qa_artifacts
LANGUAGE sql STABLE
AS $$
  SELECT * FROM qa_artifacts
  WHERE user_id = _user_id
    AND title ILIKE '%' || _query || '%'  -- concatenação DE VALOR dentro do SQL
  LIMIT 50;                               -- parametrizado é segura; de SQL, não
$$;
```

### P3 — Validação de upload (4 dimensões + nome próprio)

```typescript
const ALLOWED_MIME = new Set(["application/pdf", "text/plain", "text/markdown"]);
const MAX_UPLOAD_BYTES = 10 * 1024 * 1024; // 10 MB

function validateUpload(file: File): { ok: true; safeName: string } | { ok: false; reason: string } {
  if (file.size === 0 || file.size > MAX_UPLOAD_BYTES) {
    return { ok: false, reason: "tamanho fora do limite" };
  }
  if (!ALLOWED_MIME.has(file.type)) {
    return { ok: false, reason: `content-type não permitido: ${file.type}` };
  }
  const ext = file.name.toLowerCase().match(/\.(pdf|txt|md)$/)?.[1];
  if (!ext) return { ok: false, reason: "extensão não permitida" };

  // Nome do cliente NUNCA é usado no storage — só para exibição (e sanitizado).
  const safeName = `${crypto.randomUUID()}.${ext}`;
  return { ok: true, safeName };
}
```

> Nota: `file.type` vem do cliente e pode mentir. Para formatos críticos, validar
> também os magic bytes do conteúdo (ex.: PDF começa com `%PDF-`).

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
- [ ] Uploads validados nas 4 dimensões (extensão, content-type, tamanho, nome)?
- [ ] Nome de arquivo gravado é gerado pelo servidor?
- [ ] Todos os campos têm limite de tamanho explícito?
- [ ] Output de LLM usado pelo código também passa por schema?
