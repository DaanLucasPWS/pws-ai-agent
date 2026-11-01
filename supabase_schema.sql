create table if not exists public.user_states (
  user_id text primary key,
  state jsonb not null,
  updated_at timestamptz not null default now()
);

alter table public.user_states enable row level security;

insert into storage.buckets (id, name, public)
values ('lesmaat-files', 'lesmaat-files', false)
on conflict (id) do nothing;
