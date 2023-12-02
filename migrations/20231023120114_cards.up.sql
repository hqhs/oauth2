-- Add up migration script here

create table if not exists cards (
       card_id integer primary key,
       title text not null,
       text text not null
);
