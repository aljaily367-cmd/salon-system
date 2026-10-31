-- ════════════════════════════════════════════════════════════════
-- منظومة الصالونات v2 — متعددة الصالونات (SaaS)
-- كل صالون معزول · الحلاق يسجّل عملياته · كاش/شبكة/تحويل
-- عهدة نقدية لكل حلاق · مطابقة الشبكة والتحويل · عمولة بعد المطابقة
-- ════════════════════════════════════════════════════════════════

-- ── ٠ · إزالة نسخة v1 (بيانات تجريبية فقط) ──
drop policy if exists rc_ins on storage.objects;
drop policy if exists rc_sel on storage.objects;
drop table if exists public.ticket_items, public.discount_requests, public.payments, public.invoices, public.receipt_photos,
  public.customer_packages, public.bookings, public.tickets, public.packages, public.campaigns, public.daily_closes,
  public.incidents, public.audit_log, public.products, public.services, public.barber_pay, public.customers,
  public.profiles, public.branches cascade;
drop sequence if exists public.ticket_seq, public.invoice_seq;
do $$ declare r record; begin
  for r in select p.oid::regprocedure f from pg_proc p where p.pronamespace='public'::regnamespace loop
    execute 'drop function if exists '||r.f||' cascade'; end loop; end $$;
drop schema if exists app cascade;
delete from auth.users where email like '%@salon.test';

create schema app;

-- ── ١ · الجداول ──
create table public.tenants(
  id uuid primary key default gen_random_uuid(),
  name text not null check (length(trim(name))>=2),
  slug text not null unique check (slug ~ '^[a-z0-9-]{3,40}$'),
  vat_no text, cr_no text, phone text, city text,
  vat_registered boolean not null default true,
  active boolean not null default true,
  plan text not null default 'trial' check (plan in ('trial','monthly','yearly')),
  paid_until date,
  op_seq int not null default 0, ho_seq int not null default 0,
  created_at timestamptz not null default now());

create table public.platform_admins(email text primary key);

create table public.branches(
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id),
  name text not null, unique(tenant_id,name));

create table public.profiles(
  user_id uuid primary key references auth.users(id) on delete restrict,
  tenant_id uuid not null references public.tenants(id),
  full_name text not null,
  role text not null check (role in ('owner','supervisor','finance','barber')),
  branch_id uuid references public.branches(id),
  chair_no int,
  active boolean not null default true,
  must_change_password boolean not null default true,
  created_at timestamptz not null default now());

create table public.barber_pay(
  user_id uuid primary key references public.profiles(user_id),
  tenant_id uuid not null references public.tenants(id),
  base_salary numeric(12,2) not null default 0 check (base_salary>=0),
  service_pct numeric(5,2) not null default 0 check (service_pct between 0 and 100));

create table public.services(
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id),
  name text not null, price numeric(10,2) not null check (price>0),
  duration_min int not null default 30, active boolean not null default true,
  unique(tenant_id,name));

create table public.customers(
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id),
  full_name text not null,
  phone text not null check (phone ~ '^05[0-9]{8}$'),
  created_by uuid, created_at timestamptz not null default now(),
  unique(tenant_id,phone));

create table public.cash_handovers(
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id),
  ho_no text not null,
  barber_id uuid not null references public.profiles(user_id),
  branch_id uuid references public.branches(id),
  expected numeric(12,2) not null default 0,
  counted numeric(12,2), variance numeric(12,2),
  status text not null default 'pending' check (status in ('pending','confirmed')),
  requested_at timestamptz not null default now(),
  confirmed_by uuid, confirmed_at timestamptz, note text,
  unique(tenant_id,ho_no));

create table public.operations(
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id),
  op_no text not null,
  branch_id uuid references public.branches(id),
  barber_id uuid not null references public.profiles(user_id),
  customer_id uuid not null references public.customers(id),
  service_id uuid not null references public.services(id),
  service_name text not null,
  amount numeric(10,2) not null check (amount>0),
  method text not null check (method in ('cash','card','transfer')),
  approval_no text, transfer_name text, receipt_path text,
  status text not null default 'pending' check (status in ('pending','verified','rejected','voided')),
  handover_id uuid references public.cash_handovers(id),
  verified_by uuid, verified_at timestamptz, reason text,
  created_at timestamptz not null default now(),
  unique(tenant_id,op_no),
  check (method<>'card' or (approval_no is not null and receipt_path is not null)),
  check (method<>'transfer' or (transfer_name is not null and receipt_path is not null)));
create unique index ops_card_approval_uq on public.operations(tenant_id,approval_no) where method='card' and status<>'voided';
create index ops_tenant_date on public.operations(tenant_id,created_at);
create index ops_barber on public.operations(barber_id,status);

create table public.incidents(
  id uuid primary key default gen_random_uuid(),
  tenant_id uuid not null references public.tenants(id),
  kind text not null, ref text, details text, amount numeric(12,2),
  created_by uuid, created_at timestamptz not null default now());

create table public.audit_log(
  id bigserial primary key, tenant_id uuid, table_name text, row_id text, action text,
  before jsonb, after jsonb, actor uuid, at timestamptz not null default now());

-- ── ٢ · دوال مساعدة ──
create function app.my_tenant() returns uuid language sql stable security definer set search_path=public as
 $$ select tenant_id from public.profiles where user_id=auth.uid() and active $$;
create function app.my_role() returns text language sql stable security definer set search_path=public as
 $$ select role from public.profiles where user_id=auth.uid() and active $$;
create function app.has_role(r text[]) returns boolean language sql stable security definer set search_path=public as
 $$ select coalesce(app.my_role()=any(r),false) $$;
create function app.is_platform() returns boolean language sql stable security definer set search_path=public as
 $$ select exists(select 1 from public.platform_admins pa join auth.users u on lower(u.email)=lower(pa.email) where u.id=auth.uid()) $$;
create function app.req(r text[]) returns void language plpgsql stable security definer set search_path=public as $$
begin
  if not app.has_role(r) then raise exception 'غير مصرح لهذا الدور'; end if;
  if not exists(select 1 from public.tenants t where t.id=app.my_tenant() and t.active and (t.paid_until is null or t.paid_until>=current_date)) then
    raise exception 'اشتراك الصالون موقوف — تواصل مع مزوّد النظام'; end if;
end $$;
create function app.req_platform() returns void language plpgsql stable security definer set search_path=public as $$
begin if not app.is_platform() then raise exception 'للمزوّد فقط'; end if; end $$;
create function app.next_no(p_kind text) returns text language plpgsql security definer set search_path=public as $$
declare n int; t uuid := app.my_tenant();
begin
  if p_kind='OP' then update public.tenants set op_seq=op_seq+1 where id=t returning op_seq into n; return 'OP-'||lpad(n::text,6,'0');
  else update public.tenants set ho_seq=ho_seq+1 where id=t returning ho_seq into n; return 'HO-'||lpad(n::text,5,'0'); end if;
end $$;
create function app.create_auth_user(p_email text, p_password text) returns uuid language plpgsql security definer set search_path=public, extensions as $$
declare u uuid := gen_random_uuid(); e text := lower(trim(coalesce(p_email,'')));
begin
  if e !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then raise exception 'البريد غير صالح'; end if;
  if length(coalesce(p_password,''))<8 then raise exception 'كلمة المرور 8 أحرف على الأقل'; end if;
  if exists(select 1 from auth.users where lower(email)=e) then raise exception 'هذا البريد مسجّل مسبقًا'; end if;
  insert into auth.users(instance_id,id,aud,role,email,encrypted_password,email_confirmed_at,raw_app_meta_data,raw_user_meta_data,created_at,updated_at,confirmation_token,recovery_token,email_change,email_change_token_new)
  values('00000000-0000-0000-0000-000000000000',u,'authenticated','authenticated',e,extensions.crypt(p_password,extensions.gen_salt('bf')),now(),'{"provider":"email","providers":["email"]}','{}',now(),now(),'','','','');
  insert into auth.identities(id,user_id,provider_id,identity_data,provider,created_at,updated_at,last_sign_in_at)
  values(gen_random_uuid(),u,u::text,jsonb_build_object('sub',u::text,'email',e,'email_verified',true),'email',now(),now(),now());
  return u;
end $$;
create function app.local_date(ts timestamptz) returns date language sql immutable as $$ select (ts at time zone 'Asia/Riyadh')::date $$;

-- التدقيق ومنع الحذف
create function app.audit() returns trigger language plpgsql security definer set search_path=public as $$
declare o jsonb := case when tg_op<>'INSERT' then to_jsonb(old) end; n jsonb := case when tg_op<>'DELETE' then to_jsonb(new) end;
begin
  insert into public.audit_log(tenant_id,table_name,row_id,action,before,after,actor)
  values (coalesce(n->>'tenant_id',o->>'tenant_id')::uuid, tg_table_name, coalesce(n->>'id',n->>'user_id',o->>'id',o->>'user_id'), tg_op, o, n, auth.uid());
  return coalesce(new,old);
end $$;
create function app.no_delete() returns trigger language plpgsql set search_path=public as $$ begin raise exception 'الحذف ممنوع — استخدم الإلغاء بسبب'; end $$;
create function app.no_update() returns trigger language plpgsql set search_path=public as $$ begin raise exception 'هذا السجل لا يُعدَّل'; end $$;
do $$ declare t text; begin
  foreach t in array array['branches','profiles','barber_pay','services','customers','operations','cash_handovers'] loop
    execute format('create trigger trg_audit after insert or update or delete on public.%I for each row execute function app.audit()',t); end loop;
  foreach t in array array['operations','cash_handovers','customers','incidents','audit_log','profiles'] loop
    execute format('create trigger trg_nodel before delete on public.%I for each row execute function app.no_delete()',t); end loop;
end $$;
create trigger trg_noupd before update on public.audit_log for each row execute function app.no_update();
create trigger trg_noupd before update on public.incidents for each row execute function app.no_update();

-- ── ٣ · الأمان: عزل الصالونات (RLS) ──
do $$ declare t text; begin
  for t in select tablename from pg_tables where schemaname='public' loop
    execute format('alter table public.%I enable row level security',t); end loop; end $$;
create policy r on public.tenants for select to authenticated using (id=app.my_tenant() or app.is_platform());
create policy r on public.branches for select to authenticated using (tenant_id=app.my_tenant());
create policy r on public.services for select to authenticated using (tenant_id=app.my_tenant());
create policy r on public.profiles for select to authenticated using (tenant_id=app.my_tenant());
create policy r on public.barber_pay for select to authenticated using (tenant_id=app.my_tenant() and (app.has_role(array['owner','finance']) or user_id=auth.uid()));
create policy r on public.customers for select to authenticated using (tenant_id=app.my_tenant() and app.has_role(array['owner','supervisor','finance']));
create policy r on public.operations for select to authenticated using (tenant_id=app.my_tenant() and (app.has_role(array['owner','supervisor','finance']) or barber_id=auth.uid()));
create policy r on public.cash_handovers for select to authenticated using (tenant_id=app.my_tenant() and (app.has_role(array['owner','supervisor','finance']) or barber_id=auth.uid()));
create policy r on public.incidents for select to authenticated using (tenant_id=app.my_tenant() and app.has_role(array['owner','supervisor','finance']));
create policy r on public.audit_log for select to authenticated using (tenant_id=app.my_tenant() and app.has_role(array['owner','finance']));

insert into storage.buckets(id,name,public) values ('receipts','receipts',false) on conflict (id) do nothing;
create policy rc_ins on storage.objects for insert to authenticated with check (
  bucket_id='receipts' and (storage.foldername(name))[1]=app.my_tenant()::text and (storage.foldername(name))[2]=auth.uid()::text);
create policy rc_sel on storage.objects for select to authenticated using (
  bucket_id='receipts' and (storage.foldername(name))[1]=app.my_tenant()::text
  and (app.has_role(array['owner','supervisor','finance']) or (storage.foldername(name))[2]=auth.uid()::text));

-- ── ٤ · الدوال: الجلسة ──
create function public.me() returns jsonb language sql stable security definer set search_path=public as $$
  select jsonb_build_object(
    'uid',auth.uid(),
    'email',(select email from auth.users where id=auth.uid()),
    'platform',app.is_platform(),
    'profile',(select to_jsonb(p) from public.profiles p where p.user_id=auth.uid()),
    'branch',(select b.name from public.profiles p join public.branches b on b.id=p.branch_id where p.user_id=auth.uid()),
    'tenant',(select jsonb_build_object('id',t.id,'name',t.name,'slug',t.slug,'plan',t.plan,'paid_until',t.paid_until,'vat_registered',t.vat_registered,
               'vat_no',t.vat_no,'cr_no',t.cr_no,'phone',t.phone,'city',t.city,
               'active',t.active and (t.paid_until is null or t.paid_until>=current_date))
              from public.tenants t join public.profiles p on p.tenant_id=t.id where p.user_id=auth.uid()))
$$;
create function public.password_changed() returns void language sql security definer set search_path=public as
 $$ update public.profiles set must_change_password=false where user_id=auth.uid() $$;

-- ── ٥ · الدوال: الحلاق ──
create function public.find_customer(p_phone text) returns jsonb language plpgsql stable security definer set search_path=public as $$
declare c customers; n int;
begin
  perform app.req(array['barber','owner','supervisor']);
  select * into c from customers where tenant_id=app.my_tenant() and phone=p_phone;
  if c.id is null then return null; end if;
  select count(*) into n from operations where customer_id=c.id and status<>'voided';
  return jsonb_build_object('name',c.full_name,'visits',n);
end $$;

create function public.record_operation(p_phone text, p_name text, p_service uuid, p_method text,
  p_approval text default null, p_transfer_name text default null, p_receipt_path text default null)
returns jsonb language plpgsql security definer set search_path=public as $$
declare v_t uuid; me profiles; s services; c customers; o operations; dup text;
begin
  perform app.req(array['barber']);
  v_t := app.my_tenant();
  select * into me from profiles where user_id=auth.uid();
  select * into s from services where id=p_service and tenant_id=v_t and active;
  if s.id is null then raise exception 'اختر خدمة من القائمة'; end if;
  if p_method is null or p_method not in ('cash','card','transfer') then raise exception 'اختر طريقة السداد: كاش أو شبكة أو تحويل'; end if;
  if coalesce(p_phone,'') !~ '^05[0-9]{8}$' then raise exception 'رقم الجوال يبدأ بـ 05 ويتكون من 10 أرقام'; end if;
  if p_receipt_path is not null and p_receipt_path not like v_t::text||'/'||auth.uid()::text||'/%' then raise exception 'مسار الصورة غير صالح'; end if;
  if p_method='card' then
    p_approval := upper(trim(coalesce(p_approval,'')));
    if p_approval !~ '^[0-9A-Z]{4,12}$' then raise exception 'رقم الموافقة مطلوب (من 4 إلى 12 خانة)'; end if;
    if p_receipt_path is null then raise exception 'صورة إيصال الشبكة إلزامية'; end if;
    select op_no into dup from operations where tenant_id=v_t and method='card' and approval_no=p_approval and status<>'voided';
    if dup is not null then raise exception 'رقم الموافقة % مسجّل مسبقًا في العملية %', p_approval, dup; end if;
  elsif p_method='transfer' then
    if length(trim(coalesce(p_transfer_name,'')))<2 then raise exception 'اسم المحوِّل مطلوب'; end if;
    if p_receipt_path is null then raise exception 'صورة إشعار التحويل إلزامية'; end if;
  end if;
  select * into c from customers where tenant_id=v_t and phone=p_phone;
  if c.id is null then
    if length(trim(coalesce(p_name,'')))<2 then raise exception 'اسم العميل مطلوب للعميل الجديد'; end if;
    insert into customers(tenant_id,full_name,phone,created_by) values(v_t,trim(p_name),p_phone,auth.uid()) returning * into c;
  end if;
  insert into operations(tenant_id,op_no,branch_id,barber_id,customer_id,service_id,service_name,amount,method,approval_no,transfer_name,receipt_path)
  values(v_t,app.next_no('OP'),me.branch_id,auth.uid(),c.id,s.id,s.name,s.price,p_method,
         case when p_method='card' then p_approval end, case when p_method='transfer' then trim(p_transfer_name) end, p_receipt_path)
  returning * into o;
  return jsonb_build_object('op_no',o.op_no,'amount',o.amount,'customer',c.full_name,'service',s.name,'method',o.method,'status',o.status);
end $$;

create function public.barber_my_ops(p_from date, p_to date)
returns table(id uuid, op_no text, created_at timestamptz, customer text, service text, amount numeric, method text,
              approval_no text, transfer_name text, status text, reason text, in_handover boolean)
language sql stable security definer set search_path=public as $$
  select o.id,o.op_no,o.created_at,c.full_name,o.service_name,o.amount,o.method,o.approval_no,o.transfer_name,o.status,o.reason,o.handover_id is not null
  from operations o join customers c on c.id=o.customer_id
  where app.has_role(array['barber']) and o.barber_id=auth.uid() and app.local_date(o.created_at) between p_from and p_to
  order by o.created_at desc $$;

create function public.barber_my_customers()
returns table(full_name text, phone_masked text, visits bigint, spent numeric, last_visit timestamptz, last_service text)
language sql stable security definer set search_path=public as $$
  select c.full_name, left(c.phone,3)||'XXXX'||right(c.phone,3), count(o.id), sum(o.amount), max(o.created_at),
         (array_agg(o.service_name order by o.created_at desc))[1]
  from operations o join customers c on c.id=o.customer_id
  where app.has_role(array['barber']) and o.barber_id=auth.uid() and o.status<>'voided'
  group by c.id order by max(o.created_at) desc $$;

create function public.my_cash() returns jsonb language sql stable security definer set search_path=public as $$
  select jsonb_build_object(
    'in_hand',coalesce(sum(amount) filter (where method='cash' and status='pending' and handover_id is null),0),
    'count',count(*) filter (where method='cash' and status='pending' and handover_id is null),
    'pending',(select jsonb_build_object('id',h.id,'ho_no',h.ho_no,'expected',h.expected,'requested_at',h.requested_at)
               from cash_handovers h where h.barber_id=auth.uid() and h.status='pending'),
    'last',(select jsonb_build_object('ho_no',h.ho_no,'expected',h.expected,'counted',h.counted,'variance',h.variance,'confirmed_at',h.confirmed_at)
            from cash_handovers h where h.barber_id=auth.uid() and h.status='confirmed' order by h.confirmed_at desc limit 1))
  from operations where barber_id=auth.uid() $$;

create function public.request_handover() returns jsonb language plpgsql security definer set search_path=public as $$
declare h cash_handovers; v_sum numeric; v_n int; me profiles;
begin
  perform app.req(array['barber']);
  if exists(select 1 from cash_handovers where barber_id=auth.uid() and status='pending') then
    raise exception 'لديك تسليم سابق بانتظار الاستلام'; end if;
  select * into me from profiles where user_id=auth.uid();
  insert into cash_handovers(tenant_id,ho_no,barber_id,branch_id) values(me.tenant_id,app.next_no('HO'),auth.uid(),me.branch_id) returning * into h;
  with u as (update operations set handover_id=h.id
             where barber_id=auth.uid() and method='cash' and status='pending' and handover_id is null returning amount)
  select coalesce(sum(amount),0), count(*) into v_sum, v_n from u;
  if v_n=0 then raise exception 'لا توجد نقدية للتسليم'; end if;
  update cash_handovers set expected=v_sum where id=h.id;
  return jsonb_build_object('ho_no',h.ho_no,'expected',v_sum,'count',v_n);
end $$;

-- ── ٦ · الدوال: المراجعة والمطابقة ──
create function public.verify_operation(p_id uuid, p_ok boolean, p_reason text default null)
returns void language plpgsql security definer set search_path=public as $$
declare o operations;
begin
  perform app.req(array['owner','supervisor','finance']);
  select * into o from operations where id=p_id and tenant_id=app.my_tenant() for update;
  if o.id is null then raise exception 'العملية غير موجودة'; end if;
  if o.method='cash' then raise exception 'النقد يُطابق عند استلام العهدة من الحلاق'; end if;
  if o.status<>'pending' then raise exception 'العملية ليست بانتظار المطابقة'; end if;
  if o.barber_id=auth.uid() then raise exception 'لا تطابق عمليتك بنفسك'; end if;
  if not p_ok and length(trim(coalesce(p_reason,'')))<5 then raise exception 'سبب الرفض مطلوب'; end if;
  update operations set status=case when p_ok then 'verified' else 'rejected' end, verified_by=auth.uid(), verified_at=now(),
         reason=case when p_ok then null else p_reason end where id=p_id;
  if not p_ok then insert into incidents(tenant_id,kind,ref,details,amount,created_by)
    values(o.tenant_id,'op_rejected',o.op_no,p_reason,o.amount,auth.uid()); end if;
end $$;

create function public.match_card_report(p_rows jsonb) returns jsonb language plpgsql security definer set search_path=public as $$
declare r jsonb; o operations; a text; amt numeric; n_ok int:=0; mism jsonb:='[]'; notin jsonb:='[]';
begin
  perform app.req(array['owner','supervisor','finance']);
  for r in select * from jsonb_array_elements(coalesce(p_rows,'[]')) loop
    a := upper(trim(r->>'approval')); amt := round((r->>'amount')::numeric,2);
    select * into o from operations where tenant_id=app.my_tenant() and method='card' and approval_no=a and status<>'voided' for update;
    if o.id is null then notin := notin || jsonb_build_object('approval',a,'amount',amt);
    elsif o.status<>'pending' then continue;
    elsif o.amount<>amt then mism := mism || jsonb_build_object('op_no',o.op_no,'approval',a,'system',o.amount,'report',amt);
    elsif o.barber_id=auth.uid() then continue;
    else update operations set status='verified', verified_by=auth.uid(), verified_at=now() where id=o.id; n_ok:=n_ok+1; end if;
  end loop;
  return jsonb_build_object('matched',n_ok,'amount_mismatch',mism,'not_in_system',notin,
    'still_pending',(select count(*) from operations where tenant_id=app.my_tenant() and method='card' and status='pending'));
end $$;

create function public.confirm_handover(p_id uuid, p_counted numeric, p_note text default null)
returns jsonb language plpgsql security definer set search_path=public as $$
declare h cash_handovers;
begin
  perform app.req(array['owner','supervisor','finance']);
  select * into h from cash_handovers where id=p_id and tenant_id=app.my_tenant() for update;
  if h.id is null or h.status<>'pending' then raise exception 'التسليم غير موجود أو مستلم مسبقًا'; end if;
  if h.barber_id=auth.uid() then raise exception 'لا تستلم عهدتك بنفسك'; end if;
  if p_counted is null or p_counted<0 then raise exception 'أدخل المبلغ المعدود فعليًا'; end if;
  update cash_handovers set counted=p_counted, variance=p_counted-h.expected, status='confirmed',
         confirmed_by=auth.uid(), confirmed_at=now(), note=p_note where id=p_id;
  update operations set status='verified', verified_by=auth.uid(), verified_at=now() where handover_id=p_id and status='pending';
  if p_counted<>h.expected then insert into incidents(tenant_id,kind,ref,details,amount,created_by)
    values(h.tenant_id,'cash_variance',h.ho_no,'فرق عهدة نقدية: متوقع '||h.expected||' · معدود '||p_counted||coalesce(' · '||p_note,''),p_counted-h.expected,auth.uid()); end if;
  return jsonb_build_object('ho_no',h.ho_no,'expected',h.expected,'counted',p_counted,'variance',p_counted-h.expected);
end $$;

create function public.void_operation(p_id uuid, p_reason text) returns void language plpgsql security definer set search_path=public as $$
declare o operations;
begin
  perform app.req(array['owner','supervisor']);
  if length(trim(coalesce(p_reason,'')))<5 then raise exception 'سبب الإلغاء مطلوب'; end if;
  select * into o from operations where id=p_id and tenant_id=app.my_tenant() for update;
  if o.id is null then raise exception 'العملية غير موجودة'; end if;
  if o.status<>'pending' then raise exception 'لا تُلغى عملية مطابقة أو مرفوضة'; end if;
  if o.handover_id is not null then raise exception 'النقدية سُلّمت ضمن عهدة — راجع الاستلام أولًا'; end if;
  update operations set status='voided', reason=p_reason, verified_by=auth.uid(), verified_at=now() where id=p_id;
  insert into incidents(tenant_id,kind,ref,details,amount,created_by) values(o.tenant_id,'op_voided',o.op_no,p_reason,o.amount,auth.uid());
end $$;

create function public.dashboard(p_from date, p_to date) returns jsonb language plpgsql stable security definer set search_path=public as $$
declare v_t uuid := app.my_tenant(); res jsonb;
begin
  perform app.req(array['owner','supervisor','finance']);
  with o as (select * from operations where tenant_id=v_t and app.local_date(created_at) between p_from and p_to and status in ('pending','verified'))
  select jsonb_build_object(
    'count',(select count(*) from o), 'amount',(select coalesce(sum(amount),0) from o),
    'cash',(select coalesce(sum(amount),0) from o where method='cash'),
    'card',(select coalesce(sum(amount),0) from o where method='card'),
    'transfer',(select coalesce(sum(amount),0) from o where method='transfer'),
    'pending',(select count(*) from o where status='pending'),
    'verified',(select count(*) from o where status='verified'),
    'rejected',(select count(*) from operations where tenant_id=v_t and status='rejected' and app.local_date(created_at) between p_from and p_to),
    'customers',(select count(distinct customer_id) from o),
    'cash_in_hands',(select coalesce(sum(amount),0) from operations where tenant_id=v_t and method='cash' and status='pending' and handover_id is null),
    'handovers_pending',(select count(*) from cash_handovers where tenant_id=v_t and status='pending'),
    'incidents',(select count(*) from incidents where tenant_id=v_t and app.local_date(created_at) between p_from and p_to),
    'by_barber',(select coalesce(jsonb_agg(x order by x->>'name'),'[]') from (
        select jsonb_build_object('name',p.full_name,'chair',p.chair_no,'count',count(o.id),'amount',coalesce(sum(o.amount),0),
          'cash_in_hand',(select coalesce(sum(amount),0) from operations z where z.barber_id=p.user_id and z.method='cash' and z.status='pending' and z.handover_id is null),
          'pending',count(o.id) filter (where o.status='pending')) x
        from profiles p left join o on o.barber_id=p.user_id
        where p.tenant_id=v_t and p.role='barber' and p.active group by p.user_id) s),
    'by_service',(select coalesce(jsonb_agg(jsonb_build_object('name',service_name,'count',n,'amount',a) order by a desc),'[]')
        from (select service_name,count(*) n,sum(amount) a from o group by service_name) s)
  ) into res;
  return res;
end $$;

create function public.commission_report(p_month date)
returns table(user_id uuid, barber text, ops bigint, verified_amount numeric, net_amount numeric, pending_amount numeric,
              base_salary numeric, service_pct numeric, commission numeric, total_pay numeric)
language sql stable security definer set search_path=public as $$
  with t as (select vat_registered from tenants where id=app.my_tenant()),
  o as (select * from operations where tenant_id=app.my_tenant()
        and date_trunc('month',(created_at at time zone 'Asia/Riyadh'))=date_trunc('month',p_month::timestamp))
  select p.user_id, p.full_name,
    count(o.id) filter (where o.status='verified'),
    coalesce(sum(o.amount) filter (where o.status='verified'),0),
    round(coalesce(sum(case when (select vat_registered from t) then o.amount/1.15 else o.amount end) filter (where o.status='verified'),0),2),
    coalesce(sum(o.amount) filter (where o.status='pending'),0),
    coalesce(bp.base_salary,0), coalesce(bp.service_pct,0),
    round(coalesce(sum(case when (select vat_registered from t) then o.amount/1.15 else o.amount end) filter (where o.status='verified'),0)*coalesce(bp.service_pct,0)/100,2),
    coalesce(bp.base_salary,0)+round(coalesce(sum(case when (select vat_registered from t) then o.amount/1.15 else o.amount end) filter (where o.status='verified'),0)*coalesce(bp.service_pct,0)/100,2)
  from profiles p left join barber_pay bp on bp.user_id=p.user_id left join o on o.barber_id=p.user_id
  where p.tenant_id=app.my_tenant() and p.role='barber'
    and (app.has_role(array['owner','finance']) or p.user_id=auth.uid())
  group by p.user_id,p.full_name,bp.base_salary,bp.service_pct order by p.full_name $$;

-- ── ٧ · الدوال: المالك (إعداد الصالون) ──
create function public.update_salon(p_name text, p_vat_no text, p_cr_no text, p_phone text, p_city text, p_vat_registered boolean)
returns void language plpgsql security definer set search_path=public as $$
begin
  perform app.req(array['owner']);
  if length(trim(coalesce(p_name,'')))<2 then raise exception 'اسم الصالون مطلوب'; end if;
  if p_vat_registered and coalesce(p_vat_no,'') !~ '^3[0-9]{13}3$' then raise exception 'الرقم الضريبي 15 رقمًا يبدأ وينتهي بـ 3'; end if;
  update tenants set name=trim(p_name), vat_no=nullif(trim(p_vat_no),''), cr_no=nullif(trim(p_cr_no),''), phone=nullif(trim(p_phone),''),
         city=nullif(trim(p_city),''), vat_registered=p_vat_registered where id=app.my_tenant();
end $$;

create function public.set_branch(p_id uuid, p_name text) returns uuid language plpgsql security definer set search_path=public as $$
declare i uuid;
begin
  perform app.req(array['owner']);
  if length(trim(coalesce(p_name,'')))<2 then raise exception 'اسم الفرع مطلوب'; end if;
  if p_id is null then insert into branches(tenant_id,name) values(app.my_tenant(),trim(p_name)) returning id into i;
  else update branches set name=trim(p_name) where id=p_id and tenant_id=app.my_tenant() returning id into i;
    if i is null then raise exception 'الفرع غير موجود'; end if; end if;
  return i;
end $$;

create function public.set_service(p_id uuid, p_name text, p_price numeric, p_duration int, p_active boolean)
returns uuid language plpgsql security definer set search_path=public as $$
declare i uuid;
begin
  perform app.req(array['owner']);
  if length(trim(coalesce(p_name,'')))<2 then raise exception 'اسم الخدمة مطلوب'; end if;
  if coalesce(p_price,0)<=0 then raise exception 'السعر يجب أن يكون أكبر من صفر'; end if;
  if p_id is null then insert into services(tenant_id,name,price,duration_min,active) values(app.my_tenant(),trim(p_name),p_price,coalesce(p_duration,30),coalesce(p_active,true)) returning id into i;
  else update services set name=trim(p_name),price=p_price,duration_min=coalesce(p_duration,30),active=coalesce(p_active,true)
       where id=p_id and tenant_id=app.my_tenant() returning id into i;
    if i is null then raise exception 'الخدمة غير موجودة'; end if; end if;
  return i;
end $$;

create function public.create_staff(p_email text, p_password text, p_name text, p_role text, p_branch uuid, p_chair int default null)
returns uuid language plpgsql security definer set search_path=public as $$
declare u uuid; b uuid;
begin
  perform app.req(array['owner']);
  if p_role not in ('owner','supervisor','finance','barber') then raise exception 'دور غير صالح'; end if;
  if length(trim(coalesce(p_name,'')))<2 then raise exception 'اسم الموظف مطلوب'; end if;
  select id into b from branches where id=p_branch and tenant_id=app.my_tenant();
  if b is null then select id into b from branches where tenant_id=app.my_tenant() order by name limit 1; end if;
  u := app.create_auth_user(p_email,p_password);
  insert into profiles(user_id,tenant_id,full_name,role,branch_id,chair_no) values(u,app.my_tenant(),trim(p_name),p_role,b,p_chair);
  if p_role='barber' then insert into barber_pay(user_id,tenant_id) values(u,app.my_tenant()); end if;
  return u;
end $$;

create function public.set_staff(p_user uuid, p_role text, p_branch uuid, p_chair int, p_active boolean)
returns void language plpgsql security definer set search_path=public as $$
declare pr profiles;
begin
  perform app.req(array['owner']);
  select * into pr from profiles where user_id=p_user and tenant_id=app.my_tenant() for update;
  if pr.user_id is null then raise exception 'الموظف غير موجود'; end if;
  if p_role not in ('owner','supervisor','finance','barber') then raise exception 'دور غير صالح'; end if;
  if p_user=auth.uid() and (p_role<>'owner' or not p_active) then raise exception 'لا تغيّر دورك ولا توقف حسابك بنفسك'; end if;
  if not exists(select 1 from branches where id=p_branch and tenant_id=app.my_tenant()) then raise exception 'الفرع غير موجود'; end if;
  if pr.role='barber' and p_role<>'barber' and exists(select 1 from operations where barber_id=p_user and method='cash' and status='pending') then
    raise exception 'لدى الحلاق نقدية لم تُستلم — استلم العهدة أولًا'; end if;
  if not p_active and exists(select 1 from operations where barber_id=p_user and method='cash' and status='pending') then
    raise exception 'لدى الحلاق نقدية لم تُستلم — استلم العهدة قبل الإيقاف'; end if;
  update profiles set role=p_role, branch_id=p_branch, chair_no=p_chair, active=p_active where user_id=p_user;
  if p_role='barber' then insert into barber_pay(user_id,tenant_id) values(p_user,app.my_tenant()) on conflict (user_id) do nothing; end if;
end $$;

create function public.reset_staff_password(p_user uuid, p_password text) returns void language plpgsql security definer set search_path=public, extensions as $$
begin
  perform app.req(array['owner']);
  if not exists(select 1 from profiles where user_id=p_user and tenant_id=app.my_tenant()) then raise exception 'الموظف غير موجود'; end if;
  if length(coalesce(p_password,''))<8 then raise exception 'كلمة المرور 8 أحرف على الأقل'; end if;
  update auth.users set encrypted_password=extensions.crypt(p_password,extensions.gen_salt('bf')), updated_at=now() where id=p_user;
  update profiles set must_change_password=true where user_id=p_user;
end $$;

create function public.list_staff()
returns table(user_id uuid, full_name text, email text, role text, branch_id uuid, branch text, chair_no int, active boolean, base_salary numeric, service_pct numeric)
language sql stable security definer set search_path=public as $$
  select p.user_id,p.full_name,u.email,p.role,p.branch_id,b.name,p.chair_no,p.active,bp.base_salary,bp.service_pct
  from profiles p join auth.users u on u.id=p.user_id left join branches b on b.id=p.branch_id left join barber_pay bp on bp.user_id=p.user_id
  where app.has_role(array['owner']) and p.tenant_id=app.my_tenant() order by p.active desc, p.role, p.full_name $$;

create function public.set_barber_pay(p_user uuid, p_salary numeric, p_pct numeric) returns void language plpgsql security definer set search_path=public as $$
begin
  perform app.req(array['owner']);
  if not exists(select 1 from profiles where user_id=p_user and tenant_id=app.my_tenant() and role='barber') then raise exception 'ليس حلاقًا في صالونك'; end if;
  if p_salary<0 or p_pct<0 or p_pct>100 then raise exception 'قيم غير صالحة'; end if;
  insert into barber_pay(user_id,tenant_id,base_salary,service_pct) values(p_user,app.my_tenant(),p_salary,p_pct)
  on conflict (user_id) do update set base_salary=p_salary, service_pct=p_pct;
end $$;

-- ── ٨ · الدوال: المزوّد ──
create function public.platform_list()
returns table(id uuid, name text, slug text, plan text, paid_until date, active boolean, owner_email text,
              staff bigint, ops_30d bigint, last_op timestamptz, created_at timestamptz)
language plpgsql stable security definer set search_path=public as $$
begin
  perform app.req_platform();
  return query select t.id,t.name,t.slug,t.plan,t.paid_until,t.active,
    (select u.email from profiles p join auth.users u on u.id=p.user_id where p.tenant_id=t.id and p.role='owner' order by p.created_at limit 1)::text,
    (select count(*) from profiles p where p.tenant_id=t.id and p.active),
    (select count(*) from operations o where o.tenant_id=t.id and o.created_at>now()-interval '30 days'),
    (select max(o.created_at) from operations o where o.tenant_id=t.id), t.created_at
  from tenants t order by t.created_at desc;
end $$;

create function public.platform_create_salon(p_name text, p_slug text, p_owner_name text, p_owner_email text, p_owner_password text,
  p_plan text default 'trial', p_paid_until date default null)
returns text language plpgsql security definer set search_path=public as $$
declare t uuid; b uuid; u uuid;
begin
  perform app.req_platform();
  if p_plan not in ('trial','monthly','yearly') then raise exception 'خطة غير صالحة'; end if;
  if lower(coalesce(p_slug,'')) !~ '^[a-z0-9-]{3,40}$' then raise exception 'الرابط المختصر: حروف إنجليزية صغيرة وأرقام و- (3–40)'; end if;
  if exists(select 1 from tenants where slug=lower(p_slug)) then raise exception 'الرابط المختصر مستخدم'; end if;
  insert into tenants(name,slug,plan,paid_until) values(trim(p_name),lower(p_slug),p_plan,coalesce(p_paid_until,current_date+14)) returning id into t;
  insert into branches(tenant_id,name) values(t,'الفرع الرئيسي') returning id into b;
  u := app.create_auth_user(p_owner_email,p_owner_password);
  insert into profiles(user_id,tenant_id,full_name,role,branch_id) values(u,t,trim(p_owner_name),'owner',b);
  insert into services(tenant_id,name,price,duration_min) values
    (t,'حلاقة',50,30),(t,'لحية',30,15),(t,'حلاقة + لحية',80,45),(t,'حلاقة أطفال',35,20),(t,'صبغة',120,60),(t,'تنظيف بشرة',90,40);
  return lower(p_slug);
end $$;

create function public.platform_set_salon(p_id uuid, p_active boolean, p_plan text, p_paid_until date)
returns void language plpgsql security definer set search_path=public as $$
begin
  perform app.req_platform();
  if p_plan not in ('trial','monthly','yearly') then raise exception 'خطة غير صالحة'; end if;
  update tenants set active=p_active, plan=p_plan, paid_until=p_paid_until where id=p_id;
  if not found then raise exception 'الصالون غير موجود'; end if;
end $$;

-- ── ٩ · الصلاحيات على مستوى قاعدة البيانات ──
grant usage on schema public to anon, authenticated;
grant usage on schema app to authenticated;
revoke all on all tables in schema public from anon;
revoke insert, update, delete, truncate on all tables in schema public from authenticated;
grant select on all tables in schema public to authenticated;
revoke all on public.platform_admins from authenticated;
revoke execute on all functions in schema app from public;
grant execute on function app.my_tenant(), app.my_role(), app.has_role(text[]), app.is_platform() to authenticated;
revoke execute on all functions in schema public from public, anon;
grant execute on all functions in schema public to authenticated;
