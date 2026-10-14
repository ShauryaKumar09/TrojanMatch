-- "I am a club manager": asking for officer/advisor access to a club.
--
-- Two ways in, one queue:
--   * at sign-up, the student ticks "I am a club manager" and names a club;
--   * an existing account asks from inside the site.
--
-- Either way a row lands in club_manager_requests, every admin and the club's
-- advisors are notified, and one of them approves (choosing officer or
-- advisor) or declines. Nothing is granted until then.
--
-- Design notes:
--   * Sign-up cannot insert the row itself: with email confirmation on there
--     is no session yet. The choice rides along in the signup metadata and
--     handle_new_user() turns it into a request. That metadata is client
--     controlled, so it is only ever read as a *request*, never as a role --
--     the same stance handle_new_user already takes for app_role.
--   * The club may not exist in the directory. `club_name` keeps what the
--     person typed; only an admin can approve such a request, and must name
--     the real club (link_club) while doing it.
--   * Advisors decide only for their own club, matching grant_club_advisor
--     (advisors and admins appoint; officers appoint nobody).
--   * Nobody can write the table directly. Reads are RLS-scoped; every write
--     goes through the functions below.
--
-- Reversal: supabase/rollback/20260918000000_club_manager_requests_down.sql
-- Generated 2026-10-13.

-- --------------------------------------------------------------- 1. table --

create table if not exists public.club_manager_requests (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references public.profiles (id) on delete cascade,
  club_id      text references public.clubs (id) on delete cascade,
  club_name    text,
  message      text,
  source       text not null default 'account'
               check (source in ('signup', 'account')),
  status       public.request_status not null default 'pending',
  granted_role public.club_role,
  decided_by   uuid references public.profiles (id) on delete set null,
  decided_at   timestamptz,
  review_note  text,
  created_at   timestamptz not null default now(),
  constraint club_manager_requests_names_a_club
    check (club_id is not null or nullif(trim(club_name), '') is not null)
);

-- One live request per person per club (or per typed name, when unlisted).
create unique index if not exists club_manager_requests_one_pending_club_idx
  on public.club_manager_requests (user_id, club_id)
  where status = 'pending' and club_id is not null;

create unique index if not exists club_manager_requests_one_pending_name_idx
  on public.club_manager_requests (user_id, lower(club_name))
  where status = 'pending' and club_id is null;

create index if not exists club_manager_requests_status_idx
  on public.club_manager_requests (status, created_at desc);

-- ---------------------------------------------------------- 2. read access --

grant select on public.club_manager_requests to authenticated;
alter table public.club_manager_requests enable row level security;

drop policy if exists "users read their own manager requests" on public.club_manager_requests;
create policy "users read their own manager requests"
  on public.club_manager_requests for select to authenticated
  using (user_id = (select auth.uid()));

drop policy if exists "admins read all manager requests" on public.club_manager_requests;
create policy "admins read all manager requests"
  on public.club_manager_requests for select to authenticated
  using (public.auth_role() = 'admin');

drop policy if exists "advisors read manager requests for their club" on public.club_manager_requests;
create policy "advisors read manager requests for their club"
  on public.club_manager_requests for select to authenticated
  using (club_id is not null and public.is_club_advisor(club_id));

-- Requesters need the name of whoever is asking, and advisors cannot read
-- other people's profiles, so the queue carries who is asking itself.
create or replace function public.manager_request_queue()
returns table (
  id           uuid,
  user_id      uuid,
  requester    text,
  requester_email text,
  club_id      text,
  club_name    text,
  message      text,
  source       text,
  status       public.request_status,
  granted_role public.club_role,
  review_note  text,
  created_at   timestamptz,
  decided_at   timestamptz
)
language sql
stable
security definer
set search_path = ''
as $fn$
  select r.id, r.user_id,
         coalesce(nullif(p.full_name, ''), split_part(coalesce(p.email, ''), '@', 1)),
         p.email,
         r.club_id,
         coalesce(c.name, r.club_name),
         r.message, r.source, r.status, r.granted_role, r.review_note,
         r.created_at, r.decided_at
  from public.club_manager_requests r
  join public.profiles p on p.id = r.user_id
  left join public.clubs c on c.id = r.club_id
  where public.auth_role() = 'admin'
     or r.user_id = (select auth.uid())
     or (r.club_id is not null and public.is_club_advisor(r.club_id))
  order by (r.status = 'pending') desc, r.created_at desc
  limit 200;
$fn$;

revoke all on function public.manager_request_queue() from public;
grant execute on function public.manager_request_queue() to authenticated;

-- ------------------------------------------------------ 3. internal create --

-- Tells every admin, and the club's advisors when the club is known.
create or replace function public.notify_manager_request_reviewers(req_id uuid)
returns void
language plpgsql
security definer
set search_path = ''
as $fn$
declare
  req       public.club_manager_requests;
  who       text;
  club_label text;
  target    record;
begin
  select * into req from public.club_manager_requests where id = req_id;
  if not found then return; end if;

  select coalesce(nullif(p.full_name, ''), p.email, 'A student') into who
    from public.profiles p where p.id = req.user_id;

  select coalesce(c.name, req.club_name, 'a club') into club_label
    from (select 1) x left join public.clubs c on c.id = req.club_id;

  for target in
    select p.id from public.profiles p
     where p.role = 'admin' and p.id <> req.user_id
    union
    select m.user_id from public.memberships m
     where req.club_id is not null
       and m.club_id = req.club_id
       and m.role = 'advisor'
       and m.user_id <> req.user_id
  loop
    perform public.notify_user(
      target.id,
      'Club manager request: ' || club_label,
      who || ' asked to manage ' || club_label
        || case when req.club_id is null then ' (not in the directory yet).' else '.' end
        || ' Use Manager requests in the site header to approve or decline.',
      'request',
      req.club_id
    );
  end loop;
end;
$fn$;

revoke all on function public.notify_manager_request_reviewers(uuid) from public;

-- Shared by the sign-up trigger and the signed-in RPC. Not granted to anyone.
create or replace function public.create_manager_request(
  for_user    uuid,
  target_club text,
  typed_name  text,
  note        text,
  how         text
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $fn$
declare
  resolved text := nullif(trim(coalesce(target_club, '')), '');
  typed    text := nullif(left(trim(coalesce(typed_name, '')), 120), '');
  new_id   uuid;
begin
  -- A club id that is not real is treated as free text rather than an error:
  -- the person still gets heard, and an admin can sort out which club it was.
  if resolved is not null
     and not exists (select 1 from public.clubs c where c.id = resolved)
  then
    typed := coalesce(typed, left(resolved, 120));
    resolved := null;
  end if;

  -- Typed a name that is exactly a listed club? Treat it as that club.
  if resolved is null and typed is not null then
    select c.id into resolved
      from public.clubs c
     where lower(c.name) = lower(typed)
     limit 1;
  end if;

  if resolved is null and typed is null then
    raise exception 'Say which club you want to manage.'
      using errcode = '22023';
  end if;

  if resolved is not null and exists (
    select 1 from public.memberships m
     where m.user_id = for_user and m.club_id = resolved
       and m.role in ('officer', 'advisor')
  ) then
    raise exception 'You already help run that club.'
      using errcode = 'P0001';
  end if;

  insert into public.club_manager_requests (user_id, club_id, club_name, message, source)
  values (for_user, resolved, typed, nullif(left(trim(coalesce(note, '')), 500), ''), how)
  returning id into new_id;

  perform public.notify_manager_request_reviewers(new_id);
  return new_id;
end;
$fn$;

revoke all on function public.create_manager_request(uuid, text, text, text, text) from public;

-- -------------------------------------------------- 4. sign-up integration --

-- Same body as 20260823000000_security_hardening, plus: a signup that ticked
-- "club manager" files a request. A failure there must never block the
-- account itself, so it is swallowed.
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
  meta        jsonb := coalesce(new.raw_user_meta_data, '{}'::jsonb);
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
    nullif(trim(coalesce(meta ->> 'full_name', '')), ''),
    assigned
  )
  on conflict (id) do nothing;

  if meta ->> 'signup_intent' = 'club_manager' and assigned <> 'admin' then
    begin
      perform public.create_manager_request(
        new.id,
        meta ->> 'manager_club_id',
        meta ->> 'manager_club_name',
        meta ->> 'manager_message',
        'signup'
      );
    exception when others then
      null;
    end;
  end if;

  return new;
end;
$fn$;

-- ----------------------------------------------- 5. signed-in request RPCs --

create or replace function public.request_club_management(
  target_club text default null,
  typed_name  text default null,
  note        text default null
)
returns uuid
language plpgsql
security definer
set search_path = ''
as $fn$
begin
  if (select auth.uid()) is null then
    raise exception 'request_club_management requires an authenticated caller'
      using errcode = '42501';
  end if;

  begin
    return public.create_manager_request(
      (select auth.uid()), target_club, typed_name, note, 'account');
  exception when unique_violation then
    raise exception 'You already have a pending request for that club.'
      using errcode = 'P0001';
  end;
end;
$fn$;

revoke all on function public.request_club_management(text, text, text) from public;
grant execute on function public.request_club_management(text, text, text) to authenticated;

create or replace function public.cancel_manager_request(request_id uuid)
returns void
language sql
security definer
set search_path = ''
as $fn$
  delete from public.club_manager_requests r
   where r.id = cancel_manager_request.request_id
     and r.user_id = (select auth.uid())
     and r.status = 'pending';
$fn$;

revoke all on function public.cancel_manager_request(uuid) from public;
grant execute on function public.cancel_manager_request(uuid) to authenticated;

-- ------------------------------------------------------------ 6. deciding --

create or replace function public.decide_manager_request(
  request_id uuid,
  approve    boolean,
  grant_role public.club_role default 'officer',
  link_club  text             default null,
  note       text             default null
)
returns public.request_status
language plpgsql
security definer
set search_path = ''
as $fn$
declare
  req        public.club_manager_requests;
  target     text;
  club_label text;
  verdict    public.request_status;
  is_admin   boolean := public.auth_role() = 'admin';
begin
  select * into req from public.club_manager_requests r
   where r.id = decide_manager_request.request_id;

  if not found then
    raise exception 'no request %', decide_manager_request.request_id
      using errcode = 'P0002';
  end if;

  target := coalesce(req.club_id, nullif(trim(coalesce(link_club, '')), ''));

  -- Admins decide anything; advisors only requests for a club they advise.
  if not is_admin and not (req.club_id is not null and public.is_club_advisor(req.club_id)) then
    raise exception 'not authorised to decide this request'
      using errcode = '42501';
  end if;

  if req.status <> 'pending' then
    raise exception 'that request was already %', req.status
      using errcode = 'P0001';
  end if;

  if decide_manager_request.approve then
    if decide_manager_request.grant_role not in ('officer', 'advisor') then
      raise exception 'a club manager is an officer or an advisor'
        using errcode = '22023';
    end if;

    if target is null then
      raise exception 'That club is not in the directory yet. Add it first, then approve and pick it.'
        using errcode = 'P0001';
    end if;

    if not exists (select 1 from public.clubs c where c.id = target) then
      raise exception 'no club with id %', target using errcode = 'P0002';
    end if;
  end if;

  verdict := (case when decide_manager_request.approve then 'approved' else 'denied' end)::public.request_status;

  update public.club_manager_requests
     set status       = verdict,
         club_id      = case when verdict = 'approved' then target else club_id end,
         granted_role = case when verdict = 'approved' then decide_manager_request.grant_role end,
         decided_by   = (select auth.uid()),
         decided_at   = now(),
         review_note  = nullif(left(trim(coalesce(decide_manager_request.note, '')), 500), '')
   where id = req.id;

  if verdict = 'approved' then
    -- Never demote: an existing advisor row stays an advisor.
    insert into public.memberships (user_id, club_id, role)
    values (req.user_id, target, decide_manager_request.grant_role)
    on conflict (user_id, club_id) do update
      set role = case
        when public.memberships.role = 'advisor' then 'advisor'::public.club_role
        else excluded.role
      end;
  end if;

  select coalesce(c.name, req.club_name, 'the club') into club_label
    from (select 1) x left join public.clubs c on c.id = coalesce(target, req.club_id);

  insert into public.audit_log (actor_id, action, target_table, target_id, metadata)
  values (
    (select auth.uid()),
    'club_manager.' || verdict::text,
    'club_manager_requests',
    coalesce(target, req.club_id),
    jsonb_build_object('request', req.id, 'user', req.user_id,
                       'role', decide_manager_request.grant_role)
  );

  perform public.notify_user(
    req.user_id,
    case when verdict = 'approved'
         then 'You now help run ' || club_label
         else 'Update on your request to manage ' || club_label end,
    case when verdict = 'approved'
         then 'You were approved as ' || case decide_manager_request.grant_role
                when 'advisor' then 'an advisor' else 'an officer' end
              || '. Your club tools are on your dashboard.'
         else coalesce(nullif(trim(coalesce(decide_manager_request.note, '')), ''),
                       'Your request was not approved this time.') end,
    case when verdict = 'approved' then 'success' else 'info' end,
    coalesce(target, req.club_id)
  );

  return verdict;
end;
$fn$;

revoke all on function public.decide_manager_request(uuid, boolean, public.club_role, text, text) from public;
grant execute on function public.decide_manager_request(uuid, boolean, public.club_role, text, text) to authenticated;
