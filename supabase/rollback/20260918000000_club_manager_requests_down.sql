-- Reverses 20260918000000_club_manager_requests.sql.
-- handle_new_user() is restored to its 20260823000000_security_hardening body
-- (no club-manager request on signup); the requests themselves are dropped.
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $fn$
declare
  addr        text := lower(coalesce(new.email, ''));
  addr_domain text := split_part(addr, '@', 2);
  assigned    public.app_role := 'student';
begin
  if exists (select 1 from public.allowed_signup_domains)
     and not exists (
       select 1 from public.allowed_signup_domains d
       where lower(d.domain) = addr_domain
     )
  then
    raise exception 'Accounts are limited to school email addresses.'
      using errcode = '22023';
  end if;

  if not exists (select 1 from public.profiles p where p.role = 'admin')
     and exists (select 1 from public.bootstrap_admins b where lower(b.email) = addr)
  then
    assigned := 'admin';
  end if;

  insert into public.profiles (id, email, full_name, role)
  values (
    new.id,
    new.email,
    nullif(trim(coalesce(new.raw_user_meta_data ->> 'full_name', '')), ''),
    assigned
  )
  on conflict (id) do nothing;

  return new;
end;
$fn$;

drop function if exists public.decide_manager_request(uuid, boolean, public.club_role, text, text);
drop function if exists public.cancel_manager_request(uuid);
drop function if exists public.request_club_management(text, text, text);
drop function if exists public.create_manager_request(uuid, text, text, text, text);
drop function if exists public.notify_manager_request_reviewers(uuid);
drop function if exists public.manager_request_queue();
drop table if exists public.club_manager_requests;
