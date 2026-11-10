create function public.get_user_credits(_user_id uuid) returns integer
language sql security definer as $$
  select credits from public.profiles where user_id = _user_id;
$$;

create function public.team_stats(_team_id uuid) returns integer
language plpgsql security definer set search_path = public as $$
begin
  if not exists (select 1 from team_members where team_id = _team_id and user_id = auth.uid()) then
    raise exception 'acesso negado';
  end if;
  return (select count(*)::int from team_members where team_id = _team_id);
end $$;
revoke execute on function public.team_stats(uuid) from public, anon;

create function public.is_active() returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from public.profiles p where p.user_id = auth.uid());
$$;
revoke execute on function public.is_active() from public, anon;
grant execute on function public.is_active() to authenticated;

create function public.search_notes(_q text) returns setof public.notes
language plpgsql as $$
begin
  return query execute 'select * from public.notes where title ilike ''%' || _q || '%''';
end $$;

create function public.count_notes_like(_q text) returns bigint
language plpgsql as $$
declare _n bigint;
begin
  execute format('select count(*) from public.notes where title ilike %L', '%' || _q || '%') into _n;
  return _n;
end $$;

create view public.notes_overview as
  select n.id, n.user_id, n.title, n.created_at from public.notes n;

create view public.my_recent_notes with (security_invoker = true) as
  select n.id, n.title, n.created_at from public.notes n order by n.created_at desc;

insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
insert into storage.buckets (id, name, public) values ('documents', 'documents', false);

create function public.email_exists(_email text) returns boolean
language sql stable security definer set search_path = '' as $$
  select exists (select 1 from auth.users u where u.email = _email);
$$;

create function public.run_export(query text) returns setof json
language plpgsql security definer set search_path = '' as $$
begin
  return query execute 'select row_to_json(t) from (' || query || ') t';
end $$;
revoke execute on function public.run_export(text) from public, anon, authenticated;
