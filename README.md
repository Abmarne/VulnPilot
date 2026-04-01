# VulnPilot

VulnPilot is a Next.js web app for passive, AI-assisted secure code review of public GitHub repositories. It is designed for free-tier hosting and uses one shared server-side model to perform LLM-first vulnerability review.

## What it does

- Accepts a public GitHub repository URL and optional branch override
- Queues a passive scan job and normalizes findings into a professional report
- Reviews repository code with one shared server-configured OpenAI-compatible LLM
- Exports structured findings as JSON or Markdown
- Exports reports as JSON or Markdown

## Stack

- Next.js App Router
- TypeScript
- In-memory persistence for local development
- GitHub archive ingestion with JSZip
- LLM-first analysis with normalized remediation guidance

## Run locally

```bash
npm install
npm run dev
```

Open `http://localhost:3000`.

To enable one shared backend model, set these environment variables in your deployment secrets or local `.env.local`:

```bash
SCANNER_LLM_PROVIDER=openai-compatible
SCANNER_LLM_MODEL=gpt-4.1-mini
SCANNER_LLM_BASE_URL=https://api.openai.com/v1
SCANNER_LLM_API_KEY=your-secret-key
```

Examples:

- OpenRouter: `SCANNER_LLM_BASE_URL=https://openrouter.ai/api/v1`
- Gemini OpenAI-compatible endpoint: `SCANNER_LLM_BASE_URL=https://generativelanguage.googleapis.com/v1beta/openai`
- Hugging Face router: `SCANNER_LLM_BASE_URL=https://router.huggingface.co/v1`

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
  "branch": "canary"
}
```

## Notes and next steps

- v1 is intentionally passive and only supports public GitHub repositories.
- The current persistence layer is in-memory to keep the starter simple. Swap `lib/store.ts` for Supabase or another durable store before production deployment.
- The current LLM integration does not "train" the model. To improve results over time, keep refining prompts, add examples, and store reviewer feedback for future tuning workflows.
- For stronger production-grade coverage, pair the LLM reviewer with Semgrep, dependency advisories, or background workers in a follow-up iteration.
