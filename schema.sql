create table if not exists users (
  id          uuid primary key,
  username    text not null unique,
  created_at  timestamptz not null default now()
);

create table if not exists credentials (
  id            text primary key,          -- credential ID (base64url)
  user_id       uuid not null references users(id) on delete cascade,
  public_key    bytea not null,
  counter       bigint not null default 0,
  transports    text[],
  device_type   text,
  backed_up     boolean,
  created_at    timestamptz not null default now(),
  last_used_at  timestamptz
);

create index if not exists credentials_user_id_idx on credentials(user_id);
