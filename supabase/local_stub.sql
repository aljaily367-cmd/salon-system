-- محاكاة بيئة Supabase للاختبار المحلي فقط — لا تُطبَّق على الإنتاج
do $$ begin create role anon nologin; exception when others then null; end $$; do $$ begin create role authenticated nologin; exception when others then null; end $$;
create schema auth; create schema storage; create schema extensions;
create extension pgcrypto schema extensions;
create table auth.users(instance_id uuid, id uuid primary key, aud text, role text, email text, encrypted_password text,
 email_confirmed_at timestamptz, raw_app_meta_data jsonb, raw_user_meta_data jsonb, created_at timestamptz, updated_at timestamptz,
 confirmation_token text, recovery_token text, email_change text, email_change_token_new text);
create table auth.identities(id uuid primary key, user_id uuid, provider_id text, identity_data jsonb, provider text,
 created_at timestamptz, updated_at timestamptz, last_sign_in_at timestamptz);
create function auth.uid() returns uuid language sql stable as
 $$ select nullif(current_setting('request.jwt.claims', true)::jsonb->>'sub','')::uuid $$;
create table storage.buckets(id text primary key, name text, public boolean);
create table storage.objects(id uuid primary key default gen_random_uuid(), bucket_id text, name text);
alter table storage.objects enable row level security;
create function storage.foldername(name text) returns text[] language sql immutable as $$ select (string_to_array(name,'/'))[1:array_length(string_to_array(name,'/'),1)-1] $$;
grant usage on schema auth, storage, extensions to anon, authenticated;
grant execute on function auth.uid() to anon, authenticated;
