-- Add down migration script here

drop table if exists discord_users;
drop table if exists pending_authorizations;
drop table if exists sessions;
drop table if exists users;
