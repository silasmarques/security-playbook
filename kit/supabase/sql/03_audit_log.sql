-- Trilha de auditoria: só o servidor grava; ninguém altera nem apaga.
-- Norma: core/logging-monitoring.md R5/P2. Testes: kit/tests/sql.test.ts.

-- #region audit_log
create table public.audit_log (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null,                 -- sem FK: a trilha sobrevive à exclusão da conta
  action     text not null check (char_length(action) between 1 and 100),   -- "artifact.delete", "role.change"
  resource   text not null check (char_length(resource) between 1 and 300), -- "qa_artifacts:abc-123"
  request_id text,
  meta       jsonb not null default '{}',
  created_at timestamptz not null default now()
);

alter table public.audit_log enable row level security;        -- sem policies: nega tudo a clientes
revoke all on public.audit_log from anon, authenticated;       -- e sem grants: segunda trava
create index audit_log_user_idx on public.audit_log (user_id, created_at desc);

-- Append-only até para o service_role: um bug (ou uma chave vazada) no servidor
-- não reescreve a história. Quem apaga auditoria é só o dono do banco, por retenção.
create function public.audit_log_append_only() returns trigger
language plpgsql set search_path = '' as $$
begin
  raise exception 'audit_log is append-only';
end $$;

create trigger audit_log_no_update_delete
  before update or delete on public.audit_log
  for each row execute function public.audit_log_append_only();

revoke truncate on public.audit_log from service_role;
-- #endregion audit_log
