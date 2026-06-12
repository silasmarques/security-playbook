---
owasp: [A01]
last-review: 2026-06-11
sources:
  - https://supabase.com/docs/guides/database/postgres/row-level-security
  - https://supabase.com/docs/guides/storage/security/access-control
---

# Supabase: RLS e Acesso a Dados

> No Supabase, a anon key é pública por design — quem protege os dados é o Postgres, via Row Level Security. Tabela sem RLS no schema `public` é tabela pública. Este módulo é a aplicação concreta de `../core/authorization.md` na camada de dados.

## Regras

- **R1 — MUST** RLS habilitado em TODA tabela do schema exposto, sem exceção "temporária". A janela entre `CREATE TABLE` e `ENABLE ROW LEVEL SECURITY` na mesma migration é o máximo aceitável.
- **R2 — MUST** policies por operação (SELECT/INSERT/UPDATE/DELETE separadas). UPDATE exige `USING` (o que posso tocar) **E** `WITH CHECK` (o que o registro pode virar) — sem `WITH CHECK`, o usuário edita o próprio registro para apontar para outro dono.
- **R3 — MUST** padrão de dono: `auth.uid() = user_id`. **NEVER** `USING (true)` em tabela com dado de usuário; `to authenticated USING (true)` só para dado genuinamente público a logados (e registrado por quê).
- **R4 — MUST** lembrar que `service_role` BYPASSA RLS. Todo código server-side que usa service_role filtra explicitamente por usuário (`.eq('user_id', user.id)`) — RLS não está lá para salvar.
- **R5 — MUST** índice em toda coluna usada por policy (`user_id`, `uploaded_by`...). Policy roda em CADA linha candidata de CADA query — sem índice é full scan por request. (Uma das lacunas mais recorrentes em auditorias reais: tabela com RLS correta e sem índice na coluna de dono.)
- **R6 — MUST** Storage: bucket privado por padrão + policy por path com pasta do usuário; download via URL assinada com expiração curta. Bucket público só para asset realmente público.
- **R7 — MUST** `SECURITY DEFINER` (funções/views) roda com o dono e SEM RLS do chamador: validar acesso manualmente dentro e fixar `SET search_path = public`. Auditar cada uso novo.
- **R8 — MUST** teste de isolamento para cada tabela nova: usuário A não lê/edita dados de B. RLS sem teste é fé, não segurança.

## Padrões prontos

### P1 — Migration completa de tabela nova (o template)

```sql
CREATE TABLE qa_notes (
  id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id    uuid NOT NULL REFERENCES auth.users (id) ON DELETE CASCADE,
  title      text NOT NULL CHECK (char_length(title) <= 500),
  content    text NOT NULL CHECK (char_length(content) <= 50000),
  created_at timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE qa_notes ENABLE ROW LEVEL SECURITY;   -- na MESMA migration, sempre

CREATE POLICY "select próprio" ON qa_notes FOR SELECT
  TO authenticated USING (auth.uid() = user_id);

CREATE POLICY "insert próprio" ON qa_notes FOR INSERT
  TO authenticated WITH CHECK (auth.uid() = user_id);

CREATE POLICY "update próprio" ON qa_notes FOR UPDATE
  TO authenticated
  USING (auth.uid() = user_id)          -- o que posso tocar
  WITH CHECK (auth.uid() = user_id);    -- o que o registro pode virar

CREATE POLICY "delete próprio" ON qa_notes FOR DELETE
  TO authenticated USING (auth.uid() = user_id);

CREATE INDEX idx_qa_notes_user_id ON qa_notes (user_id);  -- R5: policy usa, índice existe
```

### P2 — Policy de Storage (pasta por usuário)

```sql
-- Bucket privado; cada usuário só enxerga sua pasta: {user_id}/arquivo.pdf
CREATE POLICY "leitura da própria pasta" ON storage.objects FOR SELECT
  TO authenticated
  USING (bucket_id = 'documents' AND (storage.foldername(name))[1] = auth.uid()::text);

CREATE POLICY "upload na própria pasta" ON storage.objects FOR INSERT
  TO authenticated
  WITH CHECK (bucket_id = 'documents' AND (storage.foldername(name))[1] = auth.uid()::text);
```

```typescript
// Download: URL assinada de vida curta, nunca bucket público
const { data } = await supabase.storage.from("documents")
  .createSignedUrl(`${user.id}/${fileId}.pdf`, 60); // 60s
```

### P3 — Teste de isolamento RLS

```typescript
// Dois clients autenticados como usuários diferentes; mesma anon key.
test("usuário B não lê notas de A", async () => {
  const noteA = await clientA.from("qa_notes")
    .insert({ title: "privada", content: "..." }).select().single();

  const { data } = await clientB.from("qa_notes").select().eq("id", noteA.data!.id);
  expect(data).toHaveLength(0);          // RLS filtra: vazio, não erro

  const upd = await clientB.from("qa_notes")
    .update({ title: "hack" }).eq("id", noteA.data!.id).select();
  expect(upd.data).toHaveLength(0);      // update não alcança a linha
});
```

### P4 — SECURITY DEFINER com guarda manual

```sql
CREATE OR REPLACE FUNCTION get_team_stats(_team_id uuid)
RETURNS TABLE (member_count int)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public AS $$
BEGIN
  -- RLS do chamador NÃO se aplica aqui — a guarda é manual e vem primeiro:
  IF NOT EXISTS (SELECT 1 FROM team_members WHERE team_id = _team_id AND user_id = auth.uid()) THEN
    RAISE EXCEPTION 'acesso negado';
  END IF;
  RETURN QUERY SELECT count(*)::int FROM team_members WHERE team_id = _team_id;
END $$;
```

## Anti-padrões

```sql
-- ❌ NUNCA: desabilitar RLS "para testar" [viola R1]
ALTER TABLE qa_notes DISABLE ROW LEVEL SECURITY;  -- e esquecer assim em prod

-- ❌ NUNCA: policy aberta em dado privado [viola R3]
CREATE POLICY "todos leem" ON qa_notes FOR SELECT USING (true);

-- ❌ NUNCA: UPDATE sem WITH CHECK [viola R2]
CREATE POLICY "update" ON qa_notes FOR UPDATE USING (auth.uid() = user_id);
-- usuário pode SET user_id = outro → transfere/planta registros
```

```typescript
// ❌ NUNCA: service_role sem filtro de dono [viola R4]
const admin = createClient(url, SERVICE_ROLE_KEY);
const { data } = await admin.from("qa_notes").select().eq("id", noteId);
// bypassa RLS e devolve a nota de QUALQUER usuário — faltou .eq('user_id', ...)
```

## Checklist

- [ ] Tabela nova: RLS + 4 policies + índice nas colunas de policy, na mesma migration?
- [ ] Policies de UPDATE têm `USING` e `WITH CHECK`?
- [ ] Nenhum `USING (true)` em dado de usuário?
- [ ] Código com service_role filtra dono explicitamente?
- [ ] Storage: bucket privado + policy por pasta + URL assinada?
- [ ] `SECURITY DEFINER` novo tem guarda manual + `search_path` fixo?
- [ ] Teste de isolamento A/B escrito e passando?
