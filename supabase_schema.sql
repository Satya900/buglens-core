-- Step 1 — Run this SQL in your Supabase SQL editor:

create table reviews (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  repo_full_name text not null,
  pr_number integer not null,
  pr_title text,
  pr_author text,
  pr_url text,
  merge_decision text check (merge_decision in ('APPROVE','REQUEST_CHANGES','COMMENT')),
  risk_summary text,
  files_reviewed integer default 0,
  findings_count integer default 0,
  gemini_model text default 'gemini-1.5-flash',
  created_at timestamptz default now()
);

create table findings (
  id uuid primary key default gen_random_uuid(),
  review_id uuid references reviews(id) on delete cascade,
  file_path text,
  line_number integer,
  severity text check (severity in ('HIGH','MEDIUM','LOW')),
  message text,
  suggestion text,
  feedback text,
  created_at timestamptz default now()
);

create table repos (
  id uuid primary key default gen_random_uuid(),
  user_id uuid references auth.users(id) on delete cascade,
  repo_full_name text not null,
  repo_id bigint,
  webhook_secret text,
  is_active boolean default true,
  total_reviews integer default 0,
  last_review_at timestamptz,
  unique(user_id, repo_full_name)
);

alter table reviews enable row level security;
alter table findings enable row level security;
alter table repos enable row level security;

create policy "users see own reviews" on reviews for all using (auth.uid() = user_id);
create policy "users see own findings" on findings for all
  using (review_id in (select id from reviews where user_id = auth.uid()));
create policy "users see own repos" on repos for all using (auth.uid() = user_id);
