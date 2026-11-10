// Validação SSRF de URL de saída + fetch com redirects revalidados.
// Norma: core/authorization.md R6/P2. Testes: kit/tests/ssrf.test.ts.
//
// O que este arquivo garante (e os testes provam):
//   - só http/https; sem credenciais embutidas na URL;
//   - hostnames internos bloqueados por nome e por sufixo;
//   - IP literal bloqueado em qualquer forma (decimal, hex, octal, comprimida,
//     IPv4-mapped/NAT64/6to4 em IPv6) — o parser WHATWG normaliza o IPv4 e aqui
//     se decodifica o IPv6 byte a byte;
//   - cada hop de redirect é revalidado; corpo lido com teto de bytes.
//
// O que NÃO garante: hostname público que RESOLVE para IP privado (DNS rebinding).
// Mitigações, em ordem de força: `allowedHosts` (destino conhecido) > `resolveHost`
// (checa os IPs resolvidos; ainda há janela entre o check e o fetch) > nada.

export type UrlCheck = { ok: true; url: URL } | { ok: false; reason: string };

export interface OutboundPolicy {
  /** Allowlist de destino. Aceita host exato ("api.exemplo.com") ou curinga de
   *  subdomínio ("*.atlassian.net"). Se informada, todo o resto é negado. */
  allowedHosts?: readonly string[];
  /** Sufixos internos adicionais do SEU ambiente (ex.: ".corp.exemplo.com"). */
  extraBlockedSuffixes?: readonly string[];
}

const MAX_URL_LENGTH = 8192;

const BLOCKED_NAMES = new Set([
  "localhost",
  "metadata.google.internal",
  "metadata.azure.com",
  "instance-data.ec2.internal",
]);

// .supabase.co/.in: a função não deve ser usada para alcançar a própria
// infraestrutura (Auth/REST/Storage) com as credenciais do ambiente.
const BLOCKED_SUFFIXES = [
  ".localhost", ".internal", ".local", ".localdomain", ".home.arpa",
  ".supabase.co", ".supabase.in",
];

// Faixas IPv4 não roteáveis publicamente: [rede, bits do prefixo].
const BLOCKED_V4: ReadonlyArray<readonly [string, number]> = [
  ["0.0.0.0", 8],        // "esta rede"
  ["10.0.0.0", 8],       // privada
  ["100.64.0.0", 10],    // CGNAT
  ["127.0.0.0", 8],      // loopback
  ["169.254.0.0", 16],   // link-local — metadata de nuvem (169.254.169.254)
  ["172.16.0.0", 12],    // privada
  ["192.0.0.0", 24],     // IETF protocol assignments
  ["192.0.2.0", 24],     // documentação
  ["192.168.0.0", 16],   // privada
  ["198.18.0.0", 15],    // benchmark
  ["198.51.100.0", 24],  // documentação
  ["203.0.113.0", 24],   // documentação
  ["224.0.0.0", 4],      // multicast
  ["240.0.0.0", 4],      // reservada + broadcast
];

function v4ToInt(parts: readonly number[]): number {
  return (((parts[0]! << 24) >>> 0) + (parts[1]! << 16) + (parts[2]! << 8) + parts[3]!) >>> 0;
}

function parseV4(host: string): number[] | null {
  const m = host.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (!m) return null;
  const parts = m.slice(1).map(Number);
  return parts.every((p) => p <= 255) ? parts : null;
}

export function isBlockedV4(parts: readonly number[]): boolean {
  const ip = v4ToInt(parts);
  return BLOCKED_V4.some(([net, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return ((ip & mask) >>> 0) === ((v4ToInt(parseV4(net)!) & mask) >>> 0);
  });
}

/** Decodifica um IPv6 textual (sem colchetes) em 16 bytes; null se inválido. */
export function parseV6(text: string): Uint8Array | null {
  let s = text;
  // sufixo IPv4 embutido (::ffff:1.2.3.4) → dois grupos hex
  const lastColon = s.lastIndexOf(":");
  const tail = s.slice(lastColon + 1);
  if (tail.includes(".")) {
    const v4 = parseV4(tail);
    if (!v4) return null;
    const hi = ((v4[0]! << 8) | v4[1]!).toString(16);
    const lo = ((v4[2]! << 8) | v4[3]!).toString(16);
    s = `${s.slice(0, lastColon + 1)}${hi}:${lo}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - rest.length;
  if (halves.length === 1 ? head.length !== 8 : missing < 1) return null;
  const groups = [...head, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...rest];
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const g = groups[i]!;
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    const n = parseInt(g, 16);
    bytes[i * 2] = n >> 8;
    bytes[i * 2 + 1] = n & 0xff;
  }
  return bytes;
}

export function isBlockedV6(b: Uint8Array): boolean {
  const allZero = (from: number, to: number) => b.slice(from, to).every((x) => x === 0);
  const embeddedV4 = (at: number) => isBlockedV4([b[at]!, b[at + 1]!, b[at + 2]!, b[at + 3]!]);

  if (allZero(0, 15) && (b[15] === 0 || b[15] === 1)) return true;        // :: e ::1
  if (allZero(0, 10) && b[10] === 0xff && b[11] === 0xff) return embeddedV4(12); // IPv4-mapped
  if (allZero(0, 12)) return embeddedV4(12);                               // IPv4-compatible (obsoleto)
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) return embeddedV4(12); // NAT64 64:ff9b::/96
  if (b[0] === 0x20 && b[1] === 0x02) return embeddedV4(2);                // 6to4 2002::/16
  if ((b[0]! & 0xfe) === 0xfc) return true;                                // fc00::/7 unique-local
  if (b[0] === 0xfe && (b[1]! & 0xc0) === 0x80) return true;               // fe80::/10 link-local
  if (b[0] === 0xff) return true;                                          // ff00::/8 multicast
  if (b[0] === 0x20 && b[1] === 0x01 && b[2] === 0x0d && b[3] === 0xb8) return true; // 2001:db8::/32 doc
  return false;
}

/** Classifica um IP textual (v4 pontilhado ou v6 sem colchetes). */
export function isBlockedIp(ip: string): boolean {
  const v4 = parseV4(ip);
  if (v4) return isBlockedV4(v4);
  const v6 = parseV6(ip);
  return v6 ? isBlockedV6(v6) : true; // não é IP reconhecível → negar (fail closed)
}

function hostAllowed(host: string, allowed: readonly string[]): boolean {
  return allowed.some((rule) => {
    const r = rule.toLowerCase();
    return r.startsWith("*.") ? host.endsWith(r.slice(1)) && host.length > r.length - 1 : host === r;
  });
}

// #region validateOutboundUrl
export function validateOutboundUrl(rawUrl: unknown, policy: OutboundPolicy = {}): UrlCheck {
  if (typeof rawUrl !== "string" || rawUrl.length === 0 || rawUrl.length > MAX_URL_LENGTH) {
    return { ok: false, reason: "URL ausente, inválida ou longa demais" };
  }
  let url: URL;
  try { url = new URL(rawUrl); } catch { return { ok: false, reason: "parse falhou" }; }

  // 1) Só http/https — nunca file:, gopher:, ftp:, data:
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    return { ok: false, reason: `protocolo não permitido: ${url.protocol}` };
  }
  // 2) Sem credenciais na URL (http://user:pass@host confunde parsers e vaza em log)
  if (url.username !== "" || url.password !== "") {
    return { ok: false, reason: "credenciais na URL não são permitidas" };
  }

  // O parser WHATWG já normalizou o host: minúsculas, IPv4 em qualquer base
  // (2130706433, 0x7f000001, 0177.0.0.1, 127.1) vira 127.0.0.1.
  const host = url.hostname.replace(/\.$/, "");

  // 3) Destino conhecido? Allowlist vence tudo — é a única defesa contra DNS rebinding.
  if (policy.allowedHosts) {
    return hostAllowed(host, policy.allowedHosts)
      ? { ok: true, url }
      : { ok: false, reason: `host fora da allowlist: ${host}` };
  }

  // 4) IP literal: classificar pela faixa, v4 e v6 (incluindo v4 embutido em v6)
  if (host.startsWith("[")) {
    const bytes = parseV6(host.slice(1, -1));
    if (!bytes || isBlockedV6(bytes)) return { ok: false, reason: `IPv6 bloqueado: ${host}` };
    return { ok: true, url };
  }
  const v4 = parseV4(host);
  if (v4) {
    return isBlockedV4(v4) ? { ok: false, reason: `IPv4 bloqueado: ${host}` } : { ok: true, url };
  }

  // 5) Hostnames internos por nome e por sufixo
  const suffixes = [...BLOCKED_SUFFIXES, ...(policy.extraBlockedSuffixes ?? [])];
  if (BLOCKED_NAMES.has(host) || !host.includes(".")) {
    return { ok: false, reason: `hostname interno: ${host}` };
  }
  if (suffixes.some((s) => host.endsWith(s))) return { ok: false, reason: `sufixo interno: ${host}` };

  return { ok: true, url };
}
// #endregion validateOutboundUrl

export class OutboundBlockedError extends Error {
  constructor(reason: string) {
    super(`requisição de saída bloqueada: ${reason}`);
    this.name = "OutboundBlockedError";
  }
}

export interface SafeFetchOptions extends OutboundPolicy {
  timeoutMs?: number;      // default 10s — vale para a cadeia inteira de redirects
  maxRedirects?: number;   // default 3
  init?: RequestInit;
  /** Resolve o hostname para IPs e bloqueia se algum for privado. Opcional:
   *  nem todo runtime expõe DNS. Reduz (não elimina) DNS rebinding. */
  resolveHost?: (hostname: string) => Promise<string[]>;
  fetchImpl?: typeof fetch; // injetável para teste
}

// #region safeFetch
/** fetch para URL de origem externa: valida, segue redirects À MÃO revalidando
 *  cada hop, e aplica um timeout único à cadeia toda. */
export async function safeFetch(rawUrl: unknown, opts: SafeFetchOptions = {}): Promise<Response> {
  const fetchImpl = opts.fetchImpl ?? fetch;
  const maxRedirects = opts.maxRedirects ?? 3;
  const signal = AbortSignal.timeout(opts.timeoutMs ?? 10_000);

  let current: unknown = rawUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    const check = validateOutboundUrl(current, opts);
    if (!check.ok) throw new OutboundBlockedError(check.reason);

    if (opts.resolveHost && !/^[\d.]+$|^\[/.test(check.url.hostname)) {
      const ips = await opts.resolveHost(check.url.hostname);
      if (ips.length === 0 || ips.some(isBlockedIp)) {
        throw new OutboundBlockedError(`host resolve para IP interno: ${check.url.hostname}`);
      }
    }

    const res = await fetchImpl(check.url, { ...opts.init, redirect: "manual", signal });
    if (res.status < 300 || res.status >= 400) return res;

    const location = res.headers.get("location");
    await res.body?.cancel();
    if (!location) throw new OutboundBlockedError("redirect sem Location");
    current = new URL(location, check.url).href; // relativo → absoluto, e volta ao topo
  }
  throw new OutboundBlockedError(`mais de ${maxRedirects} redirects`);
}
// #endregion safeFetch

/** Lê o corpo com teto: resposta maliciosa não esgota memória nem orçamento. */
export async function readBodyCapped(res: Response, maxBytes: number): Promise<Uint8Array> {
  const declared = Number(res.headers.get("content-length") ?? "0");
  if (declared > maxBytes) {
    await res.body?.cancel();
    throw new OutboundBlockedError(`resposta declara ${declared} bytes (teto ${maxBytes})`);
  }
  if (!res.body) return new Uint8Array();
  const chunks: Uint8Array[] = [];
  let total = 0;
  const reader = res.body.getReader();
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > maxBytes) {
      await reader.cancel();
      throw new OutboundBlockedError(`resposta excedeu o teto de ${maxBytes} bytes`);
    }
    chunks.push(value);
  }
  const out = new Uint8Array(total);
  let offset = 0;
  for (const c of chunks) { out.set(c, offset); offset += c.byteLength; }
  return out;
}
