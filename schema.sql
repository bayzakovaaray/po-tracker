-- Портфель проектов ПО — схема Neon Postgres.
-- Данные лежат в схеме po, к которой у Data API нет доступа.
-- Странице открыты только функции public.po_* — каждая сама проверяет код или сессию.
-- Скрипт можно запускать повторно.

create extension if not exists pgcrypto;

create schema if not exists po;
revoke all on schema po from public;

create table if not exists po.codes (
  role text primary key check (role in ('edit', 'view')),
  hash text not null,
  changed_at timestamptz not null default now()
);

create table if not exists po.sessions (
  token_hash bytea primary key,
  role text not null,
  name text not null,
  code_changed timestamptz not null,
  expires_at timestamptz not null
);

create table if not exists po.projects (
  id text primary key,
  data jsonb not null,
  updated_at timestamptz not null default now()
);

create table if not exists po.meta (k text primary key, v bigint not null);
insert into po.meta values ('ver', 0) on conflict do nothing;

create table if not exists po.login_fail (src text not null, at timestamptz not null default now());
create index if not exists login_fail_src_at on po.login_fail (src, at);

-- ---------- администрирование (вызывать из SQL Editor Neon, странице недоступно) ----------
-- select po.set_codes('код редактора', 'код просмотра');
-- Смена кодов выкидывает всех вошедших.
create or replace function po.set_codes(edit_code text, view_code text) returns text
language plpgsql set search_path = '' as $$
begin
  if length(coalesce(edit_code, '')) < 8 or length(coalesce(view_code, '')) < 8 then
    raise exception 'Коды должны быть не короче 8 символов';
  end if;
  if edit_code = view_code then raise exception 'Коды редактора и просмотра должны различаться'; end if;
  insert into po.codes (role, hash, changed_at) values
    ('edit', public.crypt(edit_code, public.gen_salt('bf', 10)), clock_timestamp()),
    ('view', public.crypt(view_code, public.gen_salt('bf', 10)), clock_timestamp())
  on conflict (role) do update set hash = excluded.hash, changed_at = excluded.changed_at;
  delete from po.sessions;
  return 'Коды установлены';
end $$;
revoke all on function po.set_codes(text, text) from public;

-- ---------- служебное ----------
create or replace function po.sess(tok text) returns po.sessions
language sql stable set search_path = '' as $$
  select s.* from po.sessions s
  join po.codes c on c.role = s.role and c.changed_at = s.code_changed
  where s.token_hash = public.digest(coalesce(tok, ''), 'sha256') and s.expires_at > now()
$$;

create or replace function po.bump() returns bigint
language sql set search_path = '' as $$
  update po.meta set v = v + 1 where k = 'ver' returning v
$$;

-- ---------- функции для страницы ----------
create or replace function public.po_login(code text, name text) returns json
language plpgsql security definer set search_path = '' as $$
declare
  n text := left(btrim(regexp_replace(coalesce(name, ''), '\s+', ' ', 'g')), 60);
  src text := coalesce(nullif(split_part(coalesce(current_setting('request.headers', true)::json ->> 'x-forwarded-for', ''), ',', 1), ''), 'all');
  r text; ch timestamptz; tok text;
begin
  if n = '' then return json_build_object('error', 'name'); end if;
  if (select count(*) from po.login_fail f where f.src = btrim(src) and f.at > now() - interval '15 minutes') >= 10 then
    return json_build_object('error', 'too_many');
  end if;
  select c.role, c.changed_at into r, ch from po.codes c where c.hash = public.crypt(coalesce(code, ''), c.hash) limit 1;
  if r is null then
    insert into po.login_fail (src) values (btrim(src));
    delete from po.login_fail where at < now() - interval '1 day';
    return json_build_object('error', 'code');
  end if;
  tok := encode(public.gen_random_bytes(32), 'hex');
  insert into po.sessions values (public.digest(tok, 'sha256'), r, n, ch, now() + interval '30 days');
  delete from po.sessions where expires_at < now();
  return json_build_object('token', tok, 'role', r, 'name', n);
end $$;

create or replace function public.po_me(tok text) returns json
language plpgsql security definer set search_path = '' as $$
declare s po.sessions;
begin
  s := po.sess(tok);
  if s.role is null then return json_build_object('error', 'auth'); end if;
  return json_build_object('role', s.role, 'name', s.name);
end $$;

create or replace function public.po_logout(tok text) returns json
language sql security definer set search_path = '' as $$
  delete from po.sessions where token_hash = public.digest(coalesce(tok, ''), 'sha256');
  select json_build_object('ok', true);
$$;

create or replace function public.po_list(tok text, since bigint default null) returns json
language plpgsql security definer set search_path = '' as $$
declare s po.sessions; ver bigint;
begin
  s := po.sess(tok);
  if s.role is null then return json_build_object('error', 'auth'); end if;
  select v into ver from po.meta where k = 'ver';
  if since is not null and since = ver then return json_build_object('version', ver, 'same', true); end if;
  return json_build_object('version', ver, 'projects',
    coalesce((select json_agg(p.data || jsonb_build_object('id', p.id)) from po.projects p), '[]'::json));
end $$;

create or replace function public.po_put(tok text, pid text, pdata jsonb) returns json
language plpgsql security definer set search_path = '' as $$
declare s po.sessions;
begin
  s := po.sess(tok);
  if s.role is null then return json_build_object('error', 'auth'); end if;
  if s.role <> 'edit' then return json_build_object('error', 'read_only'); end if;
  if pid !~ '^[A-Za-z0-9_-]{1,64}$' then return json_build_object('error', 'id'); end if;
  if jsonb_typeof(pdata) <> 'object' then return json_build_object('error', 'body'); end if;
  if octet_length(pdata::text) > 900 * 1024 then return json_build_object('error', 'too_large'); end if;
  insert into po.projects (id, data, updated_at) values (pid, pdata - 'id', now())
  on conflict (id) do update set data = excluded.data, updated_at = now();
  return json_build_object('version', po.bump());
end $$;

create or replace function public.po_delete(tok text, pid text) returns json
language plpgsql security definer set search_path = '' as $$
declare s po.sessions;
begin
  s := po.sess(tok);
  if s.role is null then return json_build_object('error', 'auth'); end if;
  if s.role <> 'edit' then return json_build_object('error', 'read_only'); end if;
  delete from po.projects where id = pid;
  return json_build_object('version', po.bump());
end $$;

-- ---------- права ----------
revoke all on function public.po_login(text, text) from public;
revoke all on function public.po_me(text) from public;
revoke all on function public.po_logout(text) from public;
revoke all on function public.po_list(text, bigint) from public;
revoke all on function public.po_put(text, text, jsonb) from public;
revoke all on function public.po_delete(text, text) from public;

do $$ begin
  if exists (select 1 from pg_roles where rolname = 'anonymous') then
    grant usage on schema public to anonymous;
    grant execute on function public.po_login(text, text), public.po_me(text), public.po_logout(text),
      public.po_list(text, bigint), public.po_put(text, text, jsonb), public.po_delete(text, text) to anonymous;
  end if;
  if exists (select 1 from pg_roles where rolname = 'authenticated') then
    grant usage on schema public to authenticated;
    grant execute on function public.po_login(text, text), public.po_me(text), public.po_logout(text),
      public.po_list(text, bigint), public.po_put(text, text, jsonb), public.po_delete(text, text) to authenticated;
  end if;
end $$;
