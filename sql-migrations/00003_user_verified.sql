\set ON_ERROR_STOP on

alter table users add column if not exists verified boolean not null default false;
