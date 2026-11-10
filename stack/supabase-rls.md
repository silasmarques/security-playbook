---
owasp: [A01]
last-review: 2026-11-10
sources:
  - https://supabase.com/docs/guides/database/postgres/row-level-security
  - https://supabase.com/docs/guides/database/functions
  - https://supabase.com/docs/guides/storage/security/access-control
  - https://www.postgresql.org/docs/current/sql-createfunction.html
  - https://www.postgresql.org/docs/current/sql-createpolicy.html
---

# Supabase: RLS e Acesso a Dados

> No Supabase, a chave do cliente (publishable key `sb_publishable_...`; anon key no modelo legado) é pública por design — quem protege os dados é o Postgres, via Row Level Security e privilégios. Tabela sem RLS no schema `public` é tabela pública. Este módulo é a aplicação concreta de `../core/authorization.md` na camada de dados. Todo o SQL daqui roda em teste contra um Postgres real ([kit/tests/sql.test.ts](../kit/tests/sql.test.ts)).

## Regras

- **R1 — MUST** RLS habilitado em TODA tabela do schema exposto, sem exceção "temporária" nem "tabela interna". `ENABLE ROW LEVEL SECURITY` vai na mesma migration do `CREATE TABLE`.
- **R2 — MUST** policies por operação (SELECT/INSERT/UPDATE/DELETE separadas), cada uma com o papel declarado (`TO authenticated`). No UPDATE, escrever `USING` (quais linhas posso tocar) **e** `WITH CHECK` (como a linha pode ficar) explicitamente. Nota de precisão: se o `WITH CHECK` for omitido, o Postgres reaproveita o `USING` — então omitir não abre brecha quando as duas condições são iguais; o explícito existe para o dia em que elas forem diferentes e para ninguém precisar lembrar dessa regra.
- **R3 — MUST** padrão de dono: `(select auth.uid()) = user_id` — o `select` faz o otimizador avaliar a função uma vez por comando em vez de uma vez por linha. **NEVER** `USING (true)` em tabela com dado de usuário; `TO authenticated USING (true)` só para dado genuinamente público a logados, com o porquê registrado.
- **R4 — MUST** lembrar que `service_role` IGNORA RLS. Todo código de servidor que usa a chave de serviço filtra explicitamente por usuário (`.eq('user_id', user.id)`) — a RLS não está lá para salvar.
- **R5 — MUST** índice em toda coluna usada por policy (`user_id`, `team_id`...). A policy roda em cada query da tabela — sem índice é varredura completa por request.
- **R6 — MUST** Storage: bucket privado por padrão + policy por pasta do usuário; download via URL assinada de vida curta. Bucket público só para asset realmente público.
- **R7 — MUST** função `SECURITY DEFINER` roda como o dono e ignora a RLS de quem chama. Três obrigações: (a) `SET search_path = ''` com schema explícito em todo objeto do corpo; (b) identidade vem de `auth.uid()` dentro da função, nunca de parâmetro; (c) `REVOKE EXECUTE … FROM public, anon` — função nova nasce executável por todos, inclusive por visitante sem login. View em schema exposto: `WITH (security_invoker = true)`, senão ela devolve as linhas de todo mundo.
- **R8 — MUST** teste de isolamento A×B para cada tabela nova: usuário B não lê, não edita, não apaga e não cria em nome de A. RLS sem teste é fé, não segurança.
- **R9 — MUST** privilégio **por coluna** quando a tabela tem campo que o usuário não pode decidir (`role`, `plan`, `credits`, `blocked_at`). A policy escolhe LINHAS, não colunas: "pode editar o próprio perfil" inclui, pela API REST, `update profiles set role = 'admin'`. `REVOKE UPDATE` da tabela e `GRANT UPDATE (colunas editáveis)`.
- **R10 — MUST** tabela só do servidor (contadores, auditoria, filas): RLS ligada, nenhuma policy **e** `REVOKE ALL … FROM anon, authenticated`. Duas travas independentes: uma policy criada por engano não abre a tabela.
- **R11 — NEVER** decidir acesso por `user_metadata` (`auth.jwt() -> 'user_metadata'`): o próprio usuário edita esse campo. Papel fica em `app_metadata` (só o servidor escreve) ou em tabela protegida.

## Padrões prontos

### P1 — Migration completa de tabela com dono (o template)

<!-- kit: kit/supabase/sql/04_owned_table_template.sql#owned_table -->
```sql
create table public.qa_notes (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid() references auth.users (id) on delete cascade,
  title      text not null check (char_length(title) between 1 and 500),
  content    text not null check (char_length(content) <= 50000),
  created_at timestamptz not null default now()
);

alter table public.qa_notes enable row level security;   -- na MESMA migration, sempre

create policy "notas: ler as próprias" on public.qa_notes for select
  to authenticated using ((select auth.uid()) = user_id);

create policy "notas: criar para si" on public.qa_notes for insert
  to authenticated with check ((select auth.uid()) = user_id);

create policy "notas: editar as próprias" on public.qa_notes for update
  to authenticated
  using ((select auth.uid()) = user_id)          -- quais linhas posso tocar
  with check ((select auth.uid()) = user_id);    -- como a linha pode ficar

create policy "notas: apagar as próprias" on public.qa_notes for delete
  to authenticated using ((select auth.uid()) = user_id);

create index qa_notes_user_id_idx on public.qa_notes (user_id);  -- a policy filtra por ela

-- anon não tem policy → não vê nada; tirar os grants é a segunda trava.
revoke all on public.qa_notes from anon;
```

### P2 — Policy de Storage (pasta por usuário)

<!-- kit: kit/supabase/sql/05_storage_policies.sql#storage_policies -->
```sql
insert into storage.buckets (id, name, public) values ('documents', 'documents', false);

create policy "documentos: ler a própria pasta" on storage.objects for select
  to authenticated
  using (bucket_id = 'documents' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy "documentos: enviar para a própria pasta" on storage.objects for insert
  to authenticated
  with check (bucket_id = 'documents' and (storage.foldername(name))[1] = (select auth.uid())::text);

create policy "documentos: apagar da própria pasta" on storage.objects for delete
  to authenticated
  using (bucket_id = 'documents' and (storage.foldername(name))[1] = (select auth.uid())::text);
-- Sem policy de UPDATE: arquivo não é sobrescrito nem movido — envia-se outro.
```

<!-- ilustrativo -->
```typescript
// Download: URL assinada de vida curta, nunca bucket público
const { data } = await supabase.storage.from("documents")
  .createSignedUrl(`${user.id}/${fileId}.pdf`, 60); // 60s
```

> As policies de Storage são testadas contra um dublê de `storage.objects`. No projeto real, confirmar com o teste A×B de upload/download.

### P3 — Teste de isolamento A×B

Dois usuários reais, o controle rodando de verdade, e um **controle positivo**: sem conferir que o dono enxerga, "B não vê nada" passaria até com a tabela vazia ou com o teste mal configurado.

<!-- ilustrativo -->
```typescript
test("usuário B não lê, não edita, não apaga e não planta dado em nome de A", async () => {
  const noteA = await clientA.from("qa_notes").insert({ title: "privada", content: "..." }).select().single();
  const id = noteA.data!.id;

  // controle positivo: A enxerga a própria nota
  expect((await clientA.from("qa_notes").select().eq("id", id)).data).toHaveLength(1);

  expect((await clientB.from("qa_notes").select().eq("id", id)).data).toHaveLength(0);
  expect((await clientB.from("qa_notes").update({ title: "hack" }).eq("id", id).select()).data).toHaveLength(0);
  expect((await clientB.from("qa_notes").delete().eq("id", id).select()).data).toHaveLength(0);

  // B tenta criar uma nota cujo dono é A → o banco recusa
  const planted = await clientB.from("qa_notes").insert({ user_id: userA.id, title: "plantada", content: "x" });
  expect(planted.error).not.toBeNull();

  // a nota de A segue intacta
  expect((await clientA.from("qa_notes").select("title").eq("id", id).single()).data!.title).toBe("privada");
});
```

### P4 — SECURITY DEFINER do jeito certo

<!-- kit: kit/supabase/sql/01_profiles_access.sql#check_user_access -->
```sql
-- SECURITY DEFINER: roda como o dono e ignora a RLS de quem chama. Por isso:
--   1. `search_path = ''` e todo objeto com schema explícito;
--   2. identidade vem de auth.uid() — NUNCA de parâmetro;
--   3. EXECUTE revogado de public e anon (o default libera para todos).
create function public.check_user_access() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (
    select 1 from public.profiles p
    where p.user_id = auth.uid() and p.blocked_at is null
  );
$$;

revoke execute on function public.check_user_access() from public, anon;
grant execute on function public.check_user_access() to authenticated;
```

### P5 — Privilégio por coluna (R9)

<!-- kit: kit/supabase/sql/01_profiles_access.sql#profiles -->
```sql
create table public.profiles (
  user_id      uuid primary key references auth.users (id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 80),
  role         text not null default 'member' check (role in ('member', 'admin')),
  plan         text not null default 'free',
  blocked_at   timestamptz,
  created_at   timestamptz not null default now()
);

alter table public.profiles enable row level security;

create policy "perfil: ler o próprio" on public.profiles for select
  to authenticated using ((select auth.uid()) = user_id);

create policy "perfil: editar o próprio" on public.profiles for update
  to authenticated
  using ((select auth.uid()) = user_id)
  with check ((select auth.uid()) = user_id);

-- A policy decide QUAIS LINHAS; não decide QUAIS COLUNAS. Sem o bloco abaixo,
-- "editar o próprio perfil" inclui `update profiles set role = 'admin'`.
-- Privilégio por coluna: o usuário só escreve no que é dele para escrever.
revoke insert, update, delete on public.profiles from anon, authenticated;
grant update (display_name) on public.profiles to authenticated;
-- INSERT/DELETE e as colunas role/plan/blocked_at: só o servidor (service_role).
```

## Anti-padrões

```sql
-- ❌ NUNCA: desabilitar RLS "para testar" [viola R1]
ALTER TABLE qa_notes DISABLE ROW LEVEL SECURITY;  -- e esquecer assim em prod

-- ❌ NUNCA: policy aberta em dado privado [viola R3]
CREATE POLICY "todos leem" ON qa_notes FOR SELECT USING (true);

-- ❌ NUNCA: policy "para o servidor" sem papel [viola R2, R10]
CREATE POLICY "service role insere" ON logs FOR INSERT WITH CHECK (true);
-- sem TO, vale para PUBLIC: qualquer visitante insere. O service_role nem precisa
-- de policy (ignora RLS) — esta só serve ao atacante.

-- ❌ NUNCA: SECURITY DEFINER com id por parâmetro e sem REVOKE [viola R7]
CREATE FUNCTION get_user_credits(_user_id uuid) RETURNS int
LANGUAGE sql SECURITY DEFINER AS $$ SELECT credits FROM profiles WHERE user_id = _user_id $$;
-- anon chama pela API com o id de qualquer pessoa

-- ❌ NUNCA: papel por user_metadata [viola R11]
CREATE POLICY "admins" ON team_members FOR SELECT
  USING ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');
-- supabase.auth.updateUser({ data: { role: 'admin' } }) e pronto

-- ❌ NUNCA: view sem security_invoker em schema exposto [viola R7]
CREATE VIEW notes_overview AS SELECT * FROM qa_notes; -- devolve as notas de todos
```

```typescript
// ❌ NUNCA: service_role sem filtro de dono [viola R4]
const admin = createClient(url, SERVICE_ROLE_KEY);
const { data } = await admin.from("qa_notes").select().eq("id", noteId);
// ignora RLS e devolve a nota de QUALQUER usuário — faltou .eq('user_id', ...)

// ❌ NUNCA: confiar que "a RLS de UPDATE está certa" basta [viola R9]
await supabase.from("profiles").update({ role: "admin" }).eq("user_id", user.id);
// a policy deixa (a linha é dele); só o privilégio por coluna barra
```

## Checklist

- [ ] Tabela nova: RLS + policies por operação com `TO <papel>` + índice nas colunas de policy, na mesma migration?
- [ ] Nenhum `USING (true)` / `WITH CHECK (true)` em dado de usuário?
- [ ] Tabela com coluna sensível tem privilégio por coluna (R9)?
- [ ] Tabela só do servidor: RLS ligada, sem policy e com `REVOKE ALL` de anon/authenticated (R10)?
- [ ] Código com service_role filtra dono explicitamente?
- [ ] Storage: bucket privado + policy por pasta + URL assinada?
- [ ] `SECURITY DEFINER`: `search_path = ''`, identidade por `auth.uid()`, `REVOKE EXECUTE` de public/anon?
- [ ] Views expostas com `security_invoker = true`?
- [ ] Nenhuma policy lê `user_metadata`?
- [ ] Teste de isolamento A×B escrito, com controle positivo, e passando?
