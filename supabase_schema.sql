-- Step 1: Run this SQL in your Supabase SQL editor.
-- This schema includes the tables referenced by the current runtime.

create table if not exists profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  github_username text unique not null,
  created_at timestamptz default now()
);

create table if not exists reviews (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  repo_full_name text not null,
  pr_number integer not null,
  pr_title text,
  pr_author text,
  pr_url text,
  merge_decision text check (merge_decision in ('APPROVE', 'REQUEST_CHANGES', 'COMMENT')),
  risk_summary text,
  files_reviewed integer default 0,
  findings_count integer default 0,
  gemini_model text default 'gemini-2.5-flash',
  created_at timestamptz default now()
);

create table if not exists findings (
  id uuid primary key default gen_random_uuid(),
  review_id uuid references reviews(id) on delete cascade,
  file_path text,
  line_number integer,
  severity text check (severity in ('HIGH', 'MEDIUM', 'LOW')),
  message text,
  suggestion text,
  feedback text,
  source text default 'ai',
  category text,
  rule_id text,
  confidence numeric(4, 3),
  created_at timestamptz default now()
);

alter table findings add column if not exists source text default 'ai';
alter table findings add column if not exists category text;
alter table findings add column if not exists rule_id text;
alter table findings add column if not exists confidence numeric(4, 3);

create table if not exists repos (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  repo_full_name text not null,
  repo_id bigint,
  webhook_secret text,
  is_active boolean default true,
  total_reviews integer default 0,
  last_review_at timestamptz,
  created_at timestamptz default now(),
  unique(user_id, repo_full_name)
);

alter table repos add column if not exists shadow_mode boolean default true;
alter table repos add column if not exists review_strictness text default 'balanced';
alter table repos add column if not exists auto_post_reviews boolean default false;

-- lessons_learned predates this schema file (it was created directly in the
-- Supabase dashboard), so it shipped with no user_id column and no RLS —
-- any authenticated user could read and delete any other user's lessons.
-- Run the backfill below once after adding the column, then verify no rows
-- are left with a null user_id before relying on the RLS policy.
create table if not exists lessons_learned (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  repo_full_name text not null,
  content text not null,
  created_at timestamptz default now()
);

alter table lessons_learned add column if not exists user_id uuid references auth.users(id) on delete cascade;

-- Backfill existing rows from repo ownership. NOTE: repo_full_name is only
-- unique per (user_id, repo_full_name), so if the same repo was ever
-- connected by more than one account, this picks one arbitrarily — review
-- the affected rows manually in that case before trusting the backfill.
update lessons_learned l
set user_id = r.user_id
from repos r
where l.repo_full_name = r.repo_full_name
  and l.user_id is null;

create table if not exists shadow_reviews (
  id uuid primary key default gen_random_uuid(),
  repo_full_name text not null,
  pr_number integer not null,
  pr_title text,
  pr_author text,
  pr_url text,
  merge_decision text,
  risk_summary text,
  files_reviewed integer default 0,
  findings_count integer default 0,
  repo_profile jsonb,
  findings_json jsonb,
  delivery_id text,
  created_at timestamptz default now()
);

-- Persisted repo index: a structural (not embedding-based) import graph for
-- each repo's default branch, refreshed on push (and on initial repo
-- connect), used to give AI reviews real cross-file context instead of a
-- live per-PR one-hop lookup (see lib/repo-index.js). Joined by
-- repo_full_name text, matching the existing shadow_reviews/lessons_learned
-- convention, not a repos.id FK.
create table if not exists repo_index_meta (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  repo_full_name text not null,
  indexed_sha text,
  status text default 'pending' check (status in ('pending', 'indexing', 'ready', 'failed')),
  file_count integer default 0,
  indexed_capped boolean default false,
  last_error text,
  last_indexed_at timestamptz,
  created_at timestamptz default now(),
  unique(user_id, repo_full_name)
);

create table if not exists repo_index_files (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  repo_full_name text not null,
  file_path text not null,
  blob_sha text not null,
  head_snippet text,
  imports jsonb default '[]'::jsonb,
  imported_by jsonb default '[]'::jsonb,
  indexed_sha text not null,
  updated_at timestamptz default now(),
  unique(user_id, repo_full_name, file_path)
);

create index if not exists reviews_repo_pr_idx on reviews (repo_full_name, pr_number, created_at desc);
create index if not exists findings_review_idx on findings (review_id);
create index if not exists repos_full_name_idx on repos (repo_full_name);
create index if not exists shadow_reviews_repo_pr_idx on shadow_reviews (repo_full_name, pr_number, created_at desc);
create index if not exists repo_index_files_repo_idx on repo_index_files (repo_full_name, file_path);
create index if not exists repo_index_meta_repo_idx on repo_index_meta (repo_full_name);

alter table profiles enable row level security;
alter table reviews enable row level security;
alter table findings enable row level security;
alter table repos enable row level security;
alter table shadow_reviews enable row level security;
alter table lessons_learned enable row level security;
alter table repo_index_meta enable row level security;
alter table repo_index_files enable row level security;

create policy "users see own profile" on profiles
for all using (auth.uid() = id);

create policy "users see own reviews" on reviews
for all using (auth.uid() = user_id);

create policy "users see own findings" on findings
for all using (
  review_id in (select id from reviews where user_id = auth.uid())
);

create policy "users see own repos" on repos
for all using (auth.uid() = user_id);

create policy "users see own shadow reviews" on shadow_reviews
for all using (
  repo_full_name in (select repo_full_name from repos where user_id = auth.uid())
);

create policy "users see own lessons" on lessons_learned
for all using (auth.uid() = user_id);

create policy "users see own repo index meta" on repo_index_meta
for all using (auth.uid() = user_id);

create policy "users see own repo index files" on repo_index_files
for all using (auth.uid() = user_id);
