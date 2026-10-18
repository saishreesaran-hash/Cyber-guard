-- ==============================================================================
-- Digital Fraud & Threat Defense Guard - Database Schema
-- Run this in your Supabase SQL Editor (Dashboard -> SQL Editor -> New query)
-- ==============================================================================

-- 1. Main scan history table
create table if not exists public.scan_history (
    id           bigint generated always as identity primary key,
    user_id      uuid references auth.users(id) on delete set null, -- Nullable for anonymous/public scans
    input_type   text        not null check (input_type in ('text', 'image', 'url', 'app_audit')),
    content      text        not null,            -- Redacted message snippet, URL, filename or summary
    verdict      text        not null,            -- Safe / Warning / High Risk / Clean / Suspicious / Malicious
    confidence   double precision,                -- 0.0 - 1.0, optional heuristic confidence score
    details      jsonb       default '{}'::jsonb, -- Redacted flags, vendor stats, forensic metrics
    created_at   timestamptz not null default now()
);

-- 2. Performance indexes
create index if not exists idx_scan_history_created_at
    on public.scan_history (created_at desc);

create index if not exists idx_scan_history_input_type
    on public.scan_history (input_type);

create index if not exists idx_scan_history_user_id
    on public.scan_history (user_id);

-- 3. Row Level Security (RLS)
alter table public.scan_history enable row level security;

-- ------------------------------------------------------------------------------
-- Policy Set A: Development / Demo Mode (Anon Access)
-- Drop these if running in a strict authenticated production environment.
-- ------------------------------------------------------------------------------
create policy "Allow anon insert" on public.scan_history
    for insert to anon with check (true);

create policy "Allow anon read" on public.scan_history
    for select to anon using (true);

-- ------------------------------------------------------------------------------
-- Policy Set B: Production Authenticated User Mode
-- Use these when Supabase Auth is enabled in your Streamlit application.
-- ------------------------------------------------------------------------------
create policy "Allow authenticated users to insert their scans" on public.scan_history
    for insert to authenticated
    with check (auth.uid() = user_id or user_id is null);

create policy "Allow authenticated users to read their own scans" on public.scan_history
    for select to authenticated
    using (auth.uid() = user_id or auth.jwt()->>'role' = 'service_role');
