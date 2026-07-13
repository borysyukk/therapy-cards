create table if not exists cards (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now(),
  template_id text not null,
  template_name text not null,
  image_data text not null,
  text_values jsonb not null default '{}'::jsonb,
  is_read boolean not null default false,
  sort_order bigint
);

alter table cards
add column if not exists sort_order bigint;

alter table cards
add column if not exists text_values jsonb not null default '{}'::jsonb;

alter table cards
add column if not exists is_read boolean not null default false;

create index if not exists cards_user_template_sort_idx
on cards (user_id, template_id, sort_order, created_at desc);

alter table cards enable row level security;

drop policy if exists "Users can read own cards" on cards;
create policy "Users can read own cards"
on cards for select
using (auth.uid() = user_id);

drop policy if exists "Users can insert own cards" on cards;
create policy "Users can insert own cards"
on cards for insert
with check (auth.uid() = user_id);

drop policy if exists "Users can delete own cards" on cards;
create policy "Users can delete own cards"
on cards for delete
using (auth.uid() = user_id);

drop policy if exists "Users can update own cards" on cards;
create policy "Users can update own cards"
on cards for update
using (auth.uid() = user_id)
with check (auth.uid() = user_id);

create table if not exists shared_cards (
  slug text primary key,
  created_at timestamptz not null default now(),
  template_id text not null,
  template_name text not null,
  description text,
  text_values jsonb not null default '{}'::jsonb
);

alter table shared_cards enable row level security;

drop policy if exists "Anyone can read shared cards" on shared_cards;
create policy "Anyone can read shared cards"
on shared_cards for select
using (true);

drop policy if exists "Anyone can create shared cards" on shared_cards;
create policy "Anyone can create shared cards"
on shared_cards for insert
with check (true);
