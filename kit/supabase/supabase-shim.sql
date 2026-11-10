-- Dublê MÍNIMO do ambiente Supabase para rodar SQL do kit (e migrations de
-- projetos) num Postgres comum. NÃO é o Supabase: reproduz só o contrato que as
-- policies usam — papéis, auth.uid()/auth.jwt(), privilégios padrão do schema
-- public e o esqueleto de storage. O que os testes provam é a semântica do
-- Postgres (RLS, GRANT, SECURITY DEFINER) sobre esse contrato.
--
-- Privilégios padrão: aqui anon/authenticated recebem TUDO em tabelas e funções
-- novas do schema public — o cenário mais permissivo. Se o SQL do kit é seguro
-- assim, é seguro com defaults mais restritos.

create role anon nologin;
create role authenticated nologin;
create role service_role nologin bypassrls;

create schema auth;
create schema storage;
create schema extensions;

create table auth.users (
  id uuid primary key default gen_random_uuid(),
  email text,
  raw_user_meta_data jsonb not null default '{}',
  raw_app_meta_data jsonb not null default '{}'
);

create function auth.jwt() returns jsonb language sql stable
  as $$ select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb $$;
create function auth.uid() returns uuid language sql stable
  as $$ select nullif(auth.jwt() ->> 'sub', '')::uuid $$;
create function auth.role() returns text language sql stable
  as $$ select auth.jwt() ->> 'role' $$;

grant usage on schema public, auth, storage, extensions to anon, authenticated, service_role;
alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public grant execute on functions to anon, authenticated, service_role;

create table storage.buckets (
  id text primary key, name text, owner uuid, public boolean not null default false,
  file_size_limit bigint, allowed_mime_types text[], created_at timestamptz default now(), updated_at timestamptz default now()
);
create table storage.objects (
  id uuid primary key default gen_random_uuid(),
  bucket_id text references storage.buckets (id),
  name text not null,
  owner uuid,
  owner_id text,
  metadata jsonb,
  user_metadata jsonb,
  path_tokens text[] generated always as (string_to_array(name, '/')) stored,
  created_at timestamptz not null default now(),
  updated_at timestamptz default now(),
  last_accessed_at timestamptz default now()
);
alter table storage.objects enable row level security;
grant all on storage.objects, storage.buckets to anon, authenticated, service_role;
create function storage.foldername(name text) returns text[] language sql immutable
  as $$ select (string_to_array(name, '/'))[1 : array_length(string_to_array(name, '/'), 1) - 1] $$;
create function storage.extension(name text) returns text language sql immutable
  as $$ select reverse(split_part(reverse(name), '.', 1)) $$;
create function storage.filename(name text) returns text language sql immutable
  as $$ select (string_to_array(name, '/'))[array_length(string_to_array(name, '/'), 1)] $$;

create publication supabase_realtime;
