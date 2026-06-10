# buglens-core

The webhook backend for [BugLens](https://buglens.dev) — receives GitHub PR events and posts AI-powered code reviews.

## Architecture

```
GitHub PR opened/updated
        │
        ▼
  POST /webhook  (HMAC-verified)
        │
        ▼
  Rate limit → Idempotency check → Billing check
        │
        ▼
  Fetch PR files → Build repo profile
        │
        ├─ Deterministic rules (secrets, eval, shell injection, typos)
        └─ Gemini 2.5 Flash per-file review + cross-file impact analysis
                    │
                    ▼
          Merge + rank findings
                    │
           shadow_mode?
          ┌─────────┴─────────┐
         YES                  NO
          │                   │
   Save to            Post inline review
  shadow_reviews      to GitHub PR +
  (no GitHub          save to reviews
   activity)          table
```

## Setup

### 1. Create a GitHub App

Go to [https://github.com/settings/apps/new](https://github.com/settings/apps/new) and configure:

- **Webhook URL:** `https://your-domain.com/webhook`
- **Webhook secret:** any random string (save it as `WEBHOOK_SECRET`)
- **Permissions:**
  - Pull requests: Read & Write
  - Issues: Read & Write
- **Subscribe to events:** Pull request, Installation

Download the private key and note the App ID.

### 2. Set up Supabase

Run `supabase_schema.sql` in your Supabase SQL editor to create all required tables.

### 3. Configure environment

```bash
cp .env.example .env
# Fill in all values
```

### 4. Install dependencies

```bash
npm install
```

### 5. Run

```bash
npm start        # development (hot reload)
node index.js    # production
```

## Environment Variables

See `.env.example` for all required variables and instructions.

## Review Strictness Levels

| Level | Min Confidence | Max Comments | REQUEST_CHANGES threshold |
|-------|---------------|--------------|--------------------------|
| relaxed | 66% | 20 | MEDIUM |
| balanced | 70% | 15 | MEDIUM |
| strict | 80% | 10 | LOW |

Configure per-repo in the BugLens dashboard.

## Scripts

| Command | Description |
|---------|-------------|
| `npm start` | Start with hot reload |
| `npm run test-webhook` | Fire a test webhook payload |
| `npm run eval:reviews` | Evaluate review quality against fixtures |

## Deployment

Designed to run on Railway, Render, or any Node.js host. Set all env vars from `.env.example` in your hosting dashboard. The server runs on `PORT` (default 3001).
