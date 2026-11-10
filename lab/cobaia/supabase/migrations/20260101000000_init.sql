create table public.profiles (
  user_id      uuid primary key references auth.users (id) on delete cascade,
  display_name text not null,
  role         text not null default 'member',
  credits      integer not null default 10,
  created_at   timestamptz not null default now()
);
alter table public.profiles enable row level security;
create policy "perfil select" on public.profiles for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "perfil update" on public.profiles for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);

create table public.notes (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null default auth.uid() references auth.users (id) on delete cascade,
  title      text not null check (char_length(title) <= 500),
  content    text not null default '',
  created_at timestamptz not null default now()
);
alter table public.notes enable row level security;
create policy "notas select" on public.notes for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "notas insert" on public.notes for insert to authenticated
  with check ((select auth.uid()) = user_id);
create policy "notas update" on public.notes for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
create policy "notas delete" on public.notes for delete to authenticated
  using ((select auth.uid()) = user_id);
create index notes_user_id_idx on public.notes (user_id);

create table public.documents (
  id         uuid primary key default gen_random_uuid(),
  owner_id   uuid not null references auth.users (id) on delete cascade,
  filename   text not null,
  content    text not null,
  created_at timestamptz not null default now()
);
alter table public.documents enable row level security;
create policy "documentos do dono" on public.documents for select to authenticated
  using (auth.uid() = owner_id);

create table public.payments (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users (id),
  amount     integer not null,
  status     text not null default 'pending',
  created_at timestamptz not null default now()
);
create index payments_user_id_idx on public.payments (user_id);

create table public.comments (
  id         uuid primary key default gen_random_uuid(),
  note_id    uuid not null references public.notes (id) on delete cascade,
  user_id    uuid not null references auth.users (id) on delete cascade,
  body       text not null,
  created_at timestamptz not null default now()
);
alter table public.comments enable row level security;
create policy "comentarios leitura" on public.comments for select to authenticated
  using (true);
create policy "comentarios escrita" on public.comments for insert to authenticated
  with check (true);

create table public.team_members (
  team_id uuid not null,
  user_id uuid not null references auth.users (id) on delete cascade,
  primary key (team_id, user_id)
);
alter table public.team_members enable row level security;
create policy "admins veem times" on public.team_members for select to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

create table public.internal_jobs (
  id         bigint generated always as identity primary key,
  kind       text not null,
  payload    jsonb not null default '{}',
  created_at timestamptz not null default now()
);
alter table public.internal_jobs enable row level security;

create table public.access_log (
  id         bigint generated always as identity primary key,
  user_id    uuid,
  path       text not null,
  created_at timestamptz not null default now()
);

create table public.user_settings (
  user_id        uuid primary key references auth.users (id) on delete cascade,
  theme          text not null default 'light',
  gemini_api_key text
);
alter table public.user_settings enable row level security;
create policy "config select" on public.user_settings for select to authenticated
  using ((select auth.uid()) = user_id);
create policy "config insert" on public.user_settings for insert to authenticated
  with check ((select auth.uid()) = user_id);
create policy "config update" on public.user_settings for update to authenticated
  using ((select auth.uid()) = user_id) with check ((select auth.uid()) = user_id);
