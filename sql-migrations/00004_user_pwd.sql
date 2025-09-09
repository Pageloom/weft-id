\set ON_ERROR_STOP on

alter table users
    add column password_hash text null
        check (
            password_hash is null or char_length(password_hash) between 60 and 255
        );
