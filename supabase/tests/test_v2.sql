-- اختبار ضوابط v2 — يُشغَّل على قاعدة محلية فقط
insert into platform_admins values ('platform@test.local');
select app.create_auth_user('platform@test.local','Platform#2026') \gset
create or replace function pg_temp.as_user(e text) returns void language sql security definer as
 $$ select set_config('request.jwt.claims', json_build_object('sub',(select id from auth.users where email=e))::text, false) $$;

create or replace function pg_temp.uid_of(e text) returns uuid language sql security definer as $$ select id from auth.users where email=e $$;
grant execute on all functions in schema pg_temp to authenticated;
set role authenticated;
do $$
declare res text := ''; ok boolean; v jsonb; n numeric; i int; A uuid; Bt uuid; svc uuid; svc50 uuid; op_card uuid; op_tr uuid; op_c2 uuid; h uuid; s text;
  procedure_dummy int;
begin
  -- ١ المزوّد ينشئ صالونين
  perform pg_temp.as_user('platform@test.local');
  perform platform_create_salon('صالون النخبة','nukhba','مالك النخبة','owner@nukhba.test','Owner#2026','yearly',current_date+365);
  perform platform_create_salon('صالون الأناقة','anaqa','مالك الأناقة','owner@anaqa.test','Owner#2026');
  select count(*) into i from platform_list(); res := res || case when i=2 then 'PASS platform-creates-2 | ' else 'FAIL1 | ' end;

  -- ٢ المالك لا يصل للوحة المزوّد
  perform pg_temp.as_user('owner@nukhba.test');
  begin perform platform_list(); res:=res||'FAIL2 | '; exception when others then res:=res||'PASS owner-no-platform | '; end;

  -- ٣ المالك ينشئ الموظفين
  perform create_staff('majed@nukhba.test','Barber#2026','ماجد','barber',null,1);
  perform create_staff('fin@nukhba.test','Finance#2026','المالية','finance',null,null);
  perform create_staff('sup@nukhba.test','Super#2026','المشرف','supervisor',null,null);
  begin perform create_staff('majed@nukhba.test','Barber#2026','مكرر','barber',null,2); res:=res||'FAIL3 | '; exception when others then res:=res||'PASS dup-email | '; end;
  perform set_barber_pay(pg_temp.uid_of('majed@nukhba.test'),3000,30);
  select id into svc from services where name='حلاقة + لحية'; select id into svc50 from services where name='حلاقة';
  perform pg_temp.as_user('owner@anaqa.test');
  perform create_staff('x@anaqa.test','Barber#2026','حلاق الأناقة','barber',null,1);

  -- ٤ الحلاق يسجّل عملياته
  perform pg_temp.as_user('majed@nukhba.test');
  select tenant_id into A from profiles where user_id=auth.uid();
  v := record_operation('0501234567','أبو فهد',svc,'cash');
  res:=res||case when (v->>'amount')::numeric=80 then 'PASS cash-80 | ' else 'FAIL4 | ' end;
  begin perform record_operation('0501234567',null,svc50,'card',null,null,A||'/'||auth.uid()||'/r.jpg'); res:=res||'FAIL5 | '; exception when others then res:=res||'PASS card-needs-approval | '; end;
  begin perform record_operation('0501234567',null,svc50,'card','482917',null,null); res:=res||'FAIL6 | '; exception when others then res:=res||'PASS card-needs-photo | '; end;
  v := record_operation('0501234567',null,svc50,'card','482917',null,A||'/'||auth.uid()||'/r1.jpg');
  begin perform record_operation('0559999999','خالد',svc50,'card','482917',null,A||'/'||auth.uid()||'/r2.jpg'); res:=res||'FAIL7 | '; exception when others then res:=res||'PASS dup-approval | '; end;
  begin perform record_operation('0559999999','خالد',svc50,'transfer',null,null,A||'/'||auth.uid()||'/r3.jpg'); res:=res||'FAIL8 | '; exception when others then res:=res||'PASS transfer-needs-name | '; end;
  begin perform record_operation('0559999999','خالد',svc50,'transfer',null,'فهد','00000000-0000-0000-0000-000000000000/x/r.jpg'); res:=res||'FAIL9 | '; exception when others then res:=res||'PASS foreign-photo-path | '; end;
  begin perform record_operation('0559999999',null,svc50,'cash'); res:=res||'FAIL10 | '; exception when others then res:=res||'PASS new-customer-needs-name | '; end;
  v := record_operation('0559999999','خالد',svc50,'transfer',null,'فهد سعد',A||'/'||auth.uid()||'/r4.jpg');
  select count(*) into i from customers; res:=res||case when i=0 then 'PASS barber-no-customer-table | ' else 'FAIL11 | ' end;
  select count(*) into i from barber_my_ops(current_date,current_date); res:=res||case when i=3 then 'PASS my-ops-3 | ' else 'FAIL12 '||i||' | ' end;
  begin insert into operations(tenant_id,op_no,barber_id,customer_id,service_id,service_name,amount,method) values(A,'X',auth.uid(),gen_random_uuid(),svc,'x',1,'cash'); res:=res||'FAIL13 | ';
  exception when others then res:=res||'PASS no-direct-insert | '; end;
  begin perform verify_operation((select id from operations where method='card'),true); res:=res||'FAIL14 | '; exception when others then res:=res||'PASS barber-cannot-verify | '; end;

  -- ٥ العزل بين الصالونات
  perform pg_temp.as_user('owner@anaqa.test');
  select count(*) into i from operations; res:=res||case when i=0 then 'PASS isolation-ops | ' else 'FAIL15 | ' end;
  select count(*) into i from customers; res:=res||case when i=0 then 'PASS isolation-customers | ' else 'FAIL16 | ' end;
  res:=res||case when find_customer('0501234567') is null then 'PASS isolation-find | ' else 'FAIL17 | ' end;
  begin perform verify_operation((select o.id from operations o limit 1),true); res:=res||'PASS(no-row) | '; exception when others then res:=res||'PASS cross-verify-blocked | '; end;

  -- ٦ المالية تطابق الشبكة والتحويل
  perform pg_temp.as_user('fin@nukhba.test');
  select id into op_card from operations where method='card'; select id into op_tr from operations where method='transfer';
  v := match_card_report('[{"approval":"482917","amount":50},{"approval":"999999","amount":20}]');
  res:=res||case when (v->>'matched')::int=1 and jsonb_array_length(v->'not_in_system')=1 then 'PASS card-report-match | ' else 'FAIL18 '||v::text||' | ' end;
  begin perform verify_operation(op_tr,false,''); res:=res||'FAIL19 | '; exception when others then res:=res||'PASS reject-needs-reason | '; end;
  perform verify_operation(op_tr,false,'لم يصل التحويل في كشف البنك');

  -- ٧ العهدة النقدية
  perform pg_temp.as_user('majed@nukhba.test');
  v := my_cash(); res:=res||case when (v->>'in_hand')::numeric=80 then 'PASS in-hand-80 | ' else 'FAIL20 '||v::text||' | ' end;
  v := request_handover(); res:=res||case when (v->>'expected')::numeric=80 then 'PASS handover-80 | ' else 'FAIL21 | ' end;
  begin perform request_handover(); res:=res||'FAIL22 | '; exception when others then res:=res||'PASS one-pending-handover | '; end;
  v := record_operation('0501234567',null,svc50,'cash');
  v := my_cash(); res:=res||case when (v->>'in_hand')::numeric=50 then 'PASS new-cash-separate | ' else 'FAIL23 | ' end;
  select id into h from cash_handovers where status='pending';
  begin perform confirm_handover(h,80); res:=res||'FAIL24 | '; exception when others then res:=res||'PASS barber-cannot-confirm | '; end;
  perform pg_temp.as_user('fin@nukhba.test');
  v := confirm_handover(h,70,'نقص 10');
  res:=res||case when (v->>'variance')::numeric=-10 then 'PASS variance--10 | ' else 'FAIL25 | ' end;
  select count(*) into i from incidents; res:=res||'incidents='||i||' | ';

  -- ٨ الإلغاء
  perform pg_temp.as_user('sup@nukhba.test');
  select id into op_c2 from operations where method='cash' and status='pending';
  begin perform void_operation(op_c2,'x'); res:=res||'FAIL26 | '; exception when others then res:=res||'PASS void-needs-reason | '; end;
  perform void_operation(op_c2,'سُجّلت بالخطأ مرتين');
  begin perform void_operation(op_card,'محاولة إلغاء مطابقة'); res:=res||'FAIL27 | '; exception when others then res:=res||'PASS no-void-verified | '; end;

  -- ٩ العمولة: المطابق 80 كاش + 50 شبكة = 130 ← صافي 113.04 ← 30% = 33.91
  perform pg_temp.as_user('owner@nukhba.test');
  select commission into n from commission_report(current_date) where barber='ماجد';
  res:=res||case when n=33.91 then 'PASS commission-33.91 | ' else 'FAIL28 '||n||' | ' end;
  v := dashboard(current_date,current_date);
  res:=res||'dash amount='||(v->>'amount')||' pending='||(v->>'pending')||' verified='||(v->>'verified')||' | ';
  perform pg_temp.as_user('majed@nukhba.test');
  select count(*) into i from commission_report(current_date); res:=res||case when i=1 then 'PASS barber-sees-own-pay | ' else 'FAIL29 | ' end;

  -- ١٠ إيقاف الحلاق ونقديته معلقة
  v := record_operation('0501234567',null,svc50,'cash');
  perform pg_temp.as_user('owner@nukhba.test');
  begin perform set_staff(pg_temp.uid_of('majed@nukhba.test'),'barber',(select id from branches limit 1),1,false); res:=res||'FAIL30 | ';
  exception when others then res:=res||'PASS no-deactivate-with-cash | '; end;
  begin perform set_staff(auth.uid(),'barber',(select id from branches limit 1),null,true); res:=res||'FAIL31 | '; exception when others then res:=res||'PASS owner-no-self-demote | '; end;

  -- ١١ إيقاف الاشتراك
  perform pg_temp.as_user('platform@test.local');
  perform platform_set_salon(A,true,'monthly',current_date-1);
  perform pg_temp.as_user('majed@nukhba.test');
  begin perform record_operation('0501234567',null,svc50,'cash'); res:=res||'FAIL32 | '; exception when others then res:=res||'PASS expired-blocks: '||sqlerrm||' | '; end;
  select count(*) into i from operations; res:=res||case when i>0 then 'PASS expired-can-read | ' else 'FAIL33 | ' end;

  raise notice '%', res;
end $$;
