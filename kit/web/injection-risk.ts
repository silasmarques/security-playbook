// Score heurístico de prompt injection para chunks de RAG (camada de DETECÇÃO).
// Norma: stack/ai-llm-security.md R6/P2. Testes: kit/tests/llm.test.ts.
//
// É blocklist: tem bypass (paráfrase, outro idioma, codificação) e tem falso
// positivo. Serve para auditar e despriorizar chunks suspeitos — nunca como a
// defesa que autoriza algo. Os testes fixam o que ela pega E o que ela não pega.

// `\b` do JavaScript só conhece ASCII: "é", "ç", "ã" contam como não-letra e a
// borda falha depois de "você agora é". Por isso bordas Unicode explícitas.
const B = String.raw`(?<![\p{L}\p{N}_])`;
const E = String.raw`(?![\p{L}\p{N}_])`;
const rx = (body: string) => new RegExp(`${B}(?:${body})${E}`, "iu");

// #region detectInjectionRisk
const INJECTION_PATTERNS: ReadonlyArray<{ flag: string; pattern: RegExp; score: number }> = [
  { flag: "ignore_previous", score: 40,
    pattern: rx(String.raw`(?:ignore|ignorar|desconsidere|desconsiderar|esqueça|esquecer|disregard|forget)${E}.{0,40}${B}(?:instruç(?:ão|ões)|regras|tudo|acima|anterior(?:es)?|previous|above|prior|all|instructions?)`) },
  { flag: "role_override", score: 25,
    pattern: rx(String.raw`você agora é|voce agora e|a partir de agora você|you are now|from now on you|act as|aja como|finja ser|pretend to be`) },
  { flag: "prompt_exfiltration", score: 40,
    pattern: rx(String.raw`(?:revele|mostre|exiba|repita|imprima|reveal|show|print|repeat)${E}.{0,40}${B}(?:prompt|system prompt|instruç(?:ão|ões) (?:do sistema|iniciais)|suas instruções|your instructions)`) },
  { flag: "secret_exfiltration", score: 40,
    pattern: rx(String.raw`(?:revele|mostre|envie|mande|reveal|show|send|leak)${E}.{0,40}${B}(?:chave|chaves|api key|api keys|senha|senhas|secret|secrets|token|tokens|credenciais|credentials)`) },
  { flag: "fake_system_turn", score: 30,
    pattern: /^\s*(?:system|assistant|sistema|assistente)\s*:/imu },
  { flag: "exfil_channel", score: 30,
    pattern: /!\[[^\]]*\]\(https?:\/\/[^)]*[?&][^)]*=/iu }, // imagem markdown com dado na query string
];

export function detectInjectionRisk(text: string): { riskScore: number; riskFlags: string[] } {
  // Normaliza truques baratos: caracteres de largura zero e formas de compatibilidade.
  const normalized = text.normalize("NFKC").replace(/[\u200B-\u200D\u2060\uFEFF]/g, "");
  const flags: string[] = [];
  let score = 0;
  for (const p of INJECTION_PATTERNS) {
    if (p.pattern.test(normalized)) { flags.push(p.flag); score += p.score; }
  }
  return { riskScore: Math.min(score, 100), riskFlags: flags.sort() };
}

/** Teto de referência: um único padrão forte (40) já tira o chunk do prompt. */
export const MAX_RISK_SCORE = 35;
// #endregion detectInjectionRisk
