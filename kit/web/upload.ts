// Validação de upload: tamanho, tipo declarado, extensão, coerência entre os
// dois e assinatura do CONTEÚDO. Nome gravado é sempre gerado pelo servidor.
// Norma: core/input-validation.md R4/P3. Testes: kit/tests/upload.test.ts.

// #region validateUpload
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
// #endregion validateUpload
