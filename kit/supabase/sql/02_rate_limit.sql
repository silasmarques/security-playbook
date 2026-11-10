-- Rate limit / cap de custo por usuário, em janela fixa.
-- Norma: core/api-security.md R2/P2. Testes: kit/tests/sql.test.ts.
--
-- Desenho: o LIMITE mora no banco (tabela rate_limits), não no argumento da
-- chamada. A função recebe só o nome da ação e conta para auth.uid(). Um
-- usuário que chame a RPC direto só consegue gastar a PRÓPRIA cota de uma ação
-- que existe — não escolhe limite, não conta para outro, não cria linhas à toa.

-- #region rate_limit
create table public.rate_limits (
  action         text primary key check (char_length(action) between 1 and 64),
  max_calls      integer not null check (max_calls > 0),
  window_seconds integer not null check (window_seconds between 1 and 2678400)
);

create table public.usage_counters (
  user_id      uuid not null references auth.users (id) on delete cascade,
  action       text not null references public.rate_limits (action) on delete cascade,
  window_start timestamptz not null,
  count        integer not null default 0,
  primary key (user_id, action, window_start)
);

-- RLS ligada e NENHUMA policy: cliente não lê nem escreve. Os grants também
-- saem — duas travas independentes (inegociável 2 vale para tabela "interna").
alter table public.rate_limits enable row level security;
alter table public.usage_counters enable row level security;
revoke all on public.rate_limits, public.usage_counters from anon, authenticated;

-- Atômica: incrementa e responde em um round-trip. true = dentro do limite.
create function public.check_and_increment(_action text) returns boolean
language plpgsql security definer set search_path = '' as $$
declare
  _uid   uuid := auth.uid();
  _rule  public.rate_limits%rowtype;
  _start timestamptz;
  _count integer;
begin
  if _uid is null then
    raise exception 'not authenticated' using errcode = '28000';
  end if;
  select * into _rule from public.rate_limits r where r.action = _action;
  if not found then
    raise exception 'unknown rate limit action' using errcode = '22023'; -- ação sem regra = erro, não "liberado"
  end if;

  _start := to_timestamp(floor(extract(epoch from now()) / _rule.window_seconds) * _rule.window_seconds);

  insert into public.usage_counters as c (user_id, action, window_start, count)
  values (_uid, _action, _start, 1)
  on conflict (user_id, action, window_start) do update set count = c.count + 1
  returning c.count into _count;

  return _count <= _rule.max_calls;
end $$;

revoke execute on function public.check_and_increment(text) from public, anon;
grant execute on function public.check_and_increment(text) to authenticated;

-- Cada ação cara ganha uma linha (na migration da feature):
--   insert into public.rate_limits values ('ai-chat', 30, 3600);
-- Limpeza: apagar janelas antigas em job agendado
--   delete from public.usage_counters where window_start < now() - interval '35 days';
-- #endregion rate_limit
