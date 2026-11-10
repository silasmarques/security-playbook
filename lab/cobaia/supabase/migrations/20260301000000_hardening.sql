alter table public.access_log enable row level security;
revoke all on public.access_log from anon, authenticated;
