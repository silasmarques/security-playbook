-- Perfil do usuário + checagem central de acesso.
-- Norma: stack/supabase-rls.md R9/P5 (privilégio por coluna), core/authorization.md R4/P1.
-- Testes: kit/tests/sql.test.ts.

-- #region profiles
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
-- #endregion profiles

-- #region check_user_access
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
-- #endregion check_user_access
