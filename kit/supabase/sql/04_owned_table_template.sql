-- Template de tabela com dono. Copiar, renomear `qa_notes` e ajustar colunas.
-- Norma: stack/supabase-rls.md R1–R5/P1. Testes: kit/tests/sql.test.ts.

-- #region owned_table
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
-- #endregion owned_table
