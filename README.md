# VulnPilot

VulnPilot is a Next.js web app for passive, AI-assisted secure code review of public GitHub repositories. It is designed for free-tier hosting and defaults to deterministic scanning so the product remains useful even without an LLM provider.

## What it does

- Accepts a public GitHub repository URL and optional branch override
- Queues a passive scan job and normalizes findings into a professional report
- Detects common risky patterns such as command execution sinks, SQL concatenation, debug mode, secret leakage, and a small set of dependency issues
- Optionally enriches the top findings with an OpenAI-compatible LLM using a user-supplied API key
- Exports reports as JSON or Markdown

## Stack

- Next.js App Router
- TypeScript
- In-memory persistence for local development
- GitHub archive ingestion with JSZip
- Rule-based analysis with curated remediation guidance

## Run locally

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

## API

- `POST /api/scans`
- `GET /api/scans`
- `GET /api/scans/:id`
- `GET /api/scans/:id/findings`
- `GET /api/scans/:id/export?format=json|md`

Example request:

```json
{
  "repoUrl": "https://github.com/vercel/next.js",
  "branch": "canary",
  "llm": {
    "provider": "openai-compatible",
    "model": "gpt-4.1-mini",
    "baseUrl": "https://api.openai.com/v1",
    "apiKey": "sk-..."
  }
}
```

## Notes and next steps

- v1 is intentionally passive and only supports public GitHub repositories.
- The current persistence layer is in-memory to keep the starter simple. Swap `lib/store.ts` for Supabase or another durable store before production deployment.
- The rule engine is intentionally lightweight. For deeper coverage, integrate Semgrep, dependency advisories, or background workers in a follow-up iteration.
