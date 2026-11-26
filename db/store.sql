-- Durable copy of Veto's private var/ folder (see server/store.js). Run once in the project's SQL editor.
-- Before running, replace <SHA-256 OF YOUR STORE SECRET> with the hex SHA-256 of the value you set as
-- VETO_STORE_SECRET:   node -e "console.log(require('crypto').createHash('sha256').update(process.argv[1]).digest('hex'))" 'your-secret'
--
-- The tables live in a schema the public API does not expose, with row-level security on and no policies.
-- The only way in is the five functions at the end, and each checks the secret first.

create schema if not exists veto;
revoke all on schema veto from anon, authenticated;

create table veto.config (key text primary key, value text not null);
create table veto.cases (id text primary key, rec jsonb not null, updated_at timestamptz not null default now());
create table veto.shots (id text primary key, jpg_b64 text not null, updated_at timestamptz not null default now());
create table veto.audit (n integer primary key, entry jsonb not null, stored_at timestamptz not null default now());
create table veto.state (key text primary key, value jsonb not null, updated_at timestamptz not null default now());

alter table veto.config enable row level security;
alter table veto.cases enable row level security;
alter table veto.shots enable row level security;
alter table veto.audit enable row level security;
alter table veto.state enable row level security;

insert into veto.config values ('secret_sha256', '<SHA-256 OF YOUR STORE SECRET>');

create or replace function veto._check(p_secret text) returns void
language plpgsql security definer set search_path = '' as $$
begin
  if p_secret is null or encode(sha256(convert_to(p_secret, 'utf8')), 'hex')
     is distinct from (select value from veto.config where key = 'secret_sha256') then
    raise exception 'forbidden' using errcode = '42501';
  end if;
end $$;

create or replace function public.veto_load(p_secret text) returns jsonb
language plpgsql security definer set search_path = '' as $$
begin
  perform veto._check(p_secret);
  return jsonb_build_object(
    'cases', coalesce((select jsonb_agg(rec order by updated_at) from veto.cases), '[]'::jsonb),
    'audit', coalesce((select jsonb_agg(entry order by n) from veto.audit), '[]'::jsonb),
    'state', coalesce((select jsonb_object_agg(key, value) from veto.state), '{}'::jsonb),
    'shots', coalesce((select jsonb_agg(id) from veto.shots), '[]'::jsonb));
end $$;

create or replace function public.veto_shot(p_secret text, p_id text) returns text
language plpgsql security definer set search_path = '' as $$
begin
  perform veto._check(p_secret);
  return (select jpg_b64 from veto.shots where id = p_id);
end $$;

create or replace function public.veto_put_case(p_secret text, p_rec jsonb, p_shot text default null) returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform veto._check(p_secret);
  insert into veto.cases (id, rec) values (p_rec->>'id', p_rec)
    on conflict (id) do update set rec = excluded.rec, updated_at = now();
  if p_shot is not null then
    insert into veto.shots (id, jpg_b64) values (p_rec->>'id', p_shot)
      on conflict (id) do update set jpg_b64 = excluded.jpg_b64, updated_at = now();
  end if;
end $$;

-- append-only: an entry number can be written once and never changed
create or replace function public.veto_append_audit(p_secret text, p_entry jsonb) returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform veto._check(p_secret);
  insert into veto.audit (n, entry) values ((p_entry->>'n')::integer, p_entry);
end $$;

create or replace function public.veto_put_state(p_secret text, p_key text, p_value jsonb) returns void
language plpgsql security definer set search_path = '' as $$
begin
  perform veto._check(p_secret);
  insert into veto.state (key, value) values (p_key, p_value)
    on conflict (key) do update set value = excluded.value, updated_at = now();
end $$;

revoke all on function veto._check(text) from public, anon, authenticated;
grant execute on function public.veto_load(text), public.veto_shot(text, text), public.veto_put_case(text, jsonb, text),
  public.veto_append_audit(text, jsonb), public.veto_put_state(text, text, jsonb) to anon;
