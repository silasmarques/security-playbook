---
owasp: [A01, A02, A05, A06]
last-review: 2026-07-03
sources:
  - https://owasp.org/www-project-web-security-testing-guide/
  - https://cheatsheetseries.owasp.org/cheatsheets/Abuse_Case_Cheat_Sheet.html
---

# Teste de Segurança

> Um controle de segurança que ninguém tentou furar é uma hipótese, não uma defesa. Este módulo transforma "pensar como atacante" em suíte de testes: para cada controle, o teste que prova que ele nega o acesso indevido. O escopo é sempre o **sistema próprio ou autorizado** — vetor de ataque na sua suíte é engenharia; contra terceiros é crime.

## Regras

- **R1 — MUST** todo controle de segurança tem **teste negativo**: o teste que prova que o acesso indevido é NEGADO, não só que o caminho feliz funciona. Controle sem teste negativo é controle não verificado.
- **R2 — MUST** todo recurso com dono tem **teste de acesso cruzado A×B**: usuário A cria, usuário B (autenticado, legítimo) tenta ler/editar/apagar → negado. É o teste que pega IDOR e falha de RLS (`../stack/supabase-rls.md` R8/P3). [A01]
- **R3 — MUST** rate limit e cap de custo se testam **estourando o limite** em teste: a chamada N+1 responde 429. Limite que nunca foi excedido em teste não se sabe se existe. [A01]
- **R4 — MUST** validação de fronteira tem teste com **input malformado, excessivo e do tipo errado** — não só o payload válido. Vetores com cara de ataque (aspas SQL, `<script>`, `../`, string gigante) são **obrigatórios na suíte**: é assim que se prova que o schema rejeita. [A05]
- **R5 — MUST** feature com superfície de segurança só está **pronta** quando os testes de segurança dela estão verdes — critério de aceite, não "depois eu adiciono".
- **R6 — NEVER** mockar o próprio controle que se quer testar (auth, RLS, validação). Mock que pula a autenticação testa o mock, não a segurança. Teste de segurança exercita o controle real.
- **R7 — MUST** toda verificação — teste automatizado, checagem de deploy, validação de mudança — precisa ser capaz de **FALHAR quando o alvo está quebrado**. Validar o **artefato/estado final real** (o que foi publicado, o que o ambiente de destino efetivamente serve), nunca um proxy que existe independentemente do resultado. Verificação que passaria mesmo com o sistema quebrado é falsa confiança — pior que nenhuma, porque encerra a investigação. Teste de mesa antes de declarar "verificado": *"se isto estivesse quebrado, este check acusaria?"* — se a resposta for não, o check está errado.

## Padrões prontos

### P1 — Teste de acesso cruzado A×B (o teste anti-IDOR)

```typescript
// Dois usuários reais autenticados; o controle (RLS/authz) roda de verdade.
test("usuário B não acessa o recurso de A", async () => {
  const created = await clientA.from("documents")
    .insert({ title: "confidencial" }).select().single();
  const id = created.data!.id;

  // B tenta LER → RLS filtra: vazio, não erro (não vaza existência)
  const read = await clientB.from("documents").select().eq("id", id);
  expect(read.data).toHaveLength(0);

  // B tenta EDITAR → não alcança a linha
  const upd = await clientB.from("documents")
    .update({ title: "hack" }).eq("id", id).select();
  expect(upd.data).toHaveLength(0);

  // B tenta APAGAR → não alcança a linha
  const del = await clientB.from("documents").delete().eq("id", id).select();
  expect(del.data).toHaveLength(0);
});
```

### P2 — Tabela de vetores de teste negativo (validação de fronteira, R4)

```typescript
// Cada vetor DEVE ser rejeitado (400/422). São dados de teste da sua própria
// suíte — não payloads operacionais contra terceiros.
const VETORES_INVALIDOS: Array<{ nome: string; valor: unknown }> = [
  { nome: "SQL-like em campo texto",  valor: "'; DROP TABLE users; --" },
  { nome: "HTML/script em campo texto", valor: "<script>alert(1)</script>" },
  { nome: "path traversal em nome de arquivo", valor: "../../etc/passwd" },
  { nome: "string acima do limite",   valor: "x".repeat(100_000) },
  { nome: "tipo errado (número onde espera texto)", valor: 12345 },
  { nome: "objeto aninhado inesperado", valor: { $ne: null } },
];

test.each(VETORES_INVALIDOS)("rejeita input inválido: $nome", ({ valor }) => {
  const r = schema.safeParse({ campo: valor });
  expect(r.success).toBe(false);   // schema é a fronteira; nada disso passa
});
```

> O ponto NÃO é "detectar SQL injection por string" (isso é blocklist, falha —
> `input-validation.md` R5). É provar que o **schema** rejeita o que não bate
> com o formato esperado. A defesa é a allowlist do schema; o teste confirma.

### P3 — Estouro de rate limit (R3)

```typescript
test("bloqueia na chamada além do limite", async () => {
  const LIMITE = 30;
  // Consome o orçamento
  for (let i = 0; i < LIMITE; i++) {
    const ok = await callEndpoint(clientA);
    expect(ok.status).toBe(200);
  }
  // N+1 → negado
  const excedido = await callEndpoint(clientA);
  expect(excedido.status).toBe(429);
});
```

### P4 — Critérios de aceite em BDD defensivo (Gherkin)

Feature com superfície de segurança carrega cenários de abuso, não só de sucesso. O cenário defensivo descreve o ataque esperado e a negação — é o critério de aceite executável.

```gherkin
Funcionalidade: Acesso a documento por ID

  Cenário: dono acessa o próprio documento
    Dado que estou autenticado como "ana"
    E existe um documento meu com id "doc-1"
    Quando eu solicito GET /documents/doc-1
    Então recebo status 200

  Cenário: usuário não acessa documento de outro (anti-IDOR)
    Dado que estou autenticado como "bruno"
    E existe um documento de "ana" com id "doc-1"
    Quando eu solicito GET /documents/doc-1
    Então recebo status 404
    E a resposta não revela se o documento existe

  Cenário: rate limit protege operação cara
    Dado que estou autenticado como "ana"
    E já fiz 30 chamadas a POST /ai/generate nesta hora
    Quando eu faço a 31ª chamada
    Então recebo status 429
```

## Anti-padrões

```typescript
// ❌ NUNCA: suíte só de caminho feliz [viola R1]
test("login funciona", async () => {
  const r = await login("ana", "senha-correta");
  expect(r.status).toBe(200);
});
// ...e nenhum teste de senha errada, lockout, token de outro usuário.

// ❌ NUNCA: mockar o controle que deveria testar [viola R6]
vi.mock("./auth", () => ({ getVerifiedUser: () => ({ id: "qualquer" }) }));
// Agora todo teste "passa" a autenticação — testou o mock, não o auth.

// ❌ NUNCA: só um usuário no teste de dados privados [viola R2]
test("usuário lê seu documento", async () => { /* só o dono, nunca o A×B */ });
// Sem o segundo usuário, IDOR/RLS quebrada passa despercebida.
```

## Checklist

- [ ] Cada controle de segurança da feature tem teste negativo (R1)?
- [ ] Recurso com dono tem teste A×B de leitura, edição e exclusão (R2)?
- [ ] Rate limit/cap testado estourando o limite → 429 (R3)?
- [ ] Validação testada com input malformado/excessivo/tipo errado (R4)?
- [ ] Testes de segurança verdes antes de considerar a feature pronta (R5)?
- [ ] Nenhum mock substituindo o controle sob teste (R6)?
- [ ] Cada verificação foi desenhada para poder falhar se o alvo estiver quebrado — valida o artefato real, não um proxy (R7)?
