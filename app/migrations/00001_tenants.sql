

create table if not exists tenants (
  id         uuid primary key default gen_random_uuid(),
  host       text not null unique,
  name       text not null default '',
  created_at timestamptz not null default now()
);
