# Assignment 2 - Full Auth.js + AI Chat Interface

[![CI](https://github.com/abdullahnaeem-commits/assignment2/actions/workflows/ci.yml/badge.svg)](https://github.com/abdullahnaeem-commits/assignment2/actions/workflows/ci.yml)

A full-stack authentication application built with SvelteKit, Auth.js, PostgreSQL, Drizzle ORM, and an AI-powered chat interface using Vercel AI SDK with Google Gemini.

## Tech Stack

- **Framework:** SvelteKit
- **Auth:** Auth.js (database sessions, OAuth, credentials)
- **Database:** PostgreSQL + Drizzle ORM
- **Styling:** TailwindCSS
- **AI Chat:** Vercel AI SDK + Google Gemini
- **Email:** Nodemailer (SMTP)

## Features

- Email/password authentication with bcrypt hashing
- Google & GitHub OAuth sign-in
- Database sessions (no JWT)
- Email verification on signup
- Password reset via secure email link
- Protected routes (dashboard, profile, chat)
- Profile management (view & update)
- Admin dashboard with user analytics, role management, and user controls
- AI chat interface with streaming responses (Vercel AI SDK + Gemini)
- Chat history stored per user in PostgreSQL
- Fully responsive UI with TailwindCSS

## Quick Start

### Prerequisites

- Node.js 18+
- PostgreSQL running locally (or a remote instance)
- pnpm (recommended) or npm

### Setup

```bash
# 1. Clone the repo
git clone https://github.com/abdullahnaeem-commits/assignment2.git
cd assignment2

# 2. Copy environment variables and fill in your secrets
cp .env.example .env

# 3. Install dependencies
pnpm install

# 4. Push database schema to PostgreSQL
pnpm db:push

# 5. Start the dev server
pnpm dev
```

### Environment Variables

Copy `.env.example` to `.env` and fill in the required values:

| Variable | Description |
|---|---|
| `DATABASE_URL` | PostgreSQL connection string |
| `AUTH_SECRET` | Random secret for Auth.js sessions |
| `GOOGLE_CLIENT_ID` | Google OAuth client ID |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret |
| `GITHUB_CLIENT_ID` | GitHub OAuth client ID |
| `GITHUB_CLIENT_SECRET` | GitHub OAuth client secret |
| `SMTP_HOST` | SMTP server host (e.g., smtp.gmail.com) |
| `SMTP_PORT` | SMTP port (e.g., 587) |
| `SMTP_USER` | SMTP email address |
| `SMTP_PASS` | SMTP password / app password |
| `GEMINI_API_KEY` | Google Gemini API key |

### Database Commands

```bash
pnpm db:push      # Push schema to database
pnpm db:migrate   # Run migrations
pnpm db:studio    # Open Drizzle Studio
pnpm db:generate  # Generate migration files
```

## Troubleshooting

### Database connection fails
- Ensure PostgreSQL is running on the correct port
- Verify `DATABASE_URL` in `.env` matches your PostgreSQL credentials

### OAuth not working
- Google: Set authorized redirect URI to `http://localhost:5173/auth/callback/google`
- GitHub: Set callback URL to `http://localhost:5173/auth/callback/github`

### Emails not sending
- For Gmail: enable 2FA and generate an App Password
- Use the App Password as `SMTP_PASS`, not your regular password

### AI Chat not responding
- Verify `GEMINI_API_KEY` is set in `.env`
- Get a key from [Google AI Studio](https://aistudio.google.com/apikey)
