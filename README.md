# VulnPilot

> The world's first fully automated active security platform.

VulnPilot is a context-aware security assistant that finds, verifies, fixes, and explains vulnerabilities in real time. It combines live web-app testing, source-code analysis, replayable evidence, and AI-assisted remediation in one workflow.

---

## Core Superpowers

### The War Room
A real-time dashboard streams logs, progress, and findings over WebSockets.
- Multi-stage pipeline: `init -> profile -> recon -> sca -> sast -> logic -> dast -> analysis`
- Live finding stream with remediation and replay evidence

### The Active Fixer
Turn findings into secure code with one click.
- AI-powered refactoring for local source files
- Secure remediation snippets and developer-facing steps

### Authenticated Attack Profiles
Import real authenticated traffic and replay it during scanning for deeper pentest coverage.
- HAR import for many requests captured from a browser session
- cURL import for one important authenticated API request
- Replayable evidence with baseline request, mutated request, status delta, and replay cURL

### Deep Active-Offensive Engine
- Bespoke AI fuzzing tied to discovered parameters and sinks
- Logic and IDOR auditing
- Dependency scanning
- Taint-chasing SAST to reduce false positives

---

## Getting Started

### 1. Clone and Configure
```bash
git clone https://github.com/Abmarne/VulnPilot.git
cd VulnPilot
```

Create a `.env` file in `backend/`:
```env
GOOGLE_API_KEY=your_gemini_key_here
GROQ_API_KEY=your_groq_key_here
```

### 2. Install Dependencies
Backend:
```bash
cd backend
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Frontend:
```bash
cd ../frontend
npm install
```

### 3. Start the App
Backend:
```bash
cd ../backend
.venv\Scripts\python.exe main.py
```

Frontend:
```bash
cd ../frontend
npm run dev
```

Open `http://localhost:3000`.

---

## Using Authenticated Attack Profiles

Authenticated attack profiles help VulnPilot reach logged-in pages, dashboards, and internal APIs that a normal crawler may miss.

### What `Import HAR` Means
`Import HAR` means uploading a HAR file exported from your browser DevTools Network tab.

A HAR file contains real traffic from your session, including:
- request URLs
- HTTP methods
- headers
- cookies
- request bodies

Use HAR import when you want VulnPilot to learn a full authenticated workflow from a real browser session.

### What `Import cURL Profile` Means
`Import cURL Profile` means pasting one real cURL command into the dashboard.

Use cURL import when you want to target one important authenticated API request quickly.

### HAR vs cURL
- `HAR`: best for many requests captured from a browser session
- `cURL`: best for one specific API request or endpoint

### How To Export a HAR File
In Chrome or Edge:
1. Open DevTools.
2. Open the `Network` tab.
3. Log in and perform the actions you want VulnPilot to learn.
4. Right-click the request list.
5. Choose `Save all as HAR with content`.

### How To Use It In VulnPilot
1. Start the backend and frontend.
2. Open `http://localhost:3000`.
3. Enter the target URL in the main target field.
4. Import one of the following:
   - a HAR file in `Import HAR Profile`
   - a cURL command in `Import cURL Profile`
5. Select the saved profile from `Saved Attack Profile`.
6. Keep `Use profile requests` enabled.
7. Launch the scan.

### Example cURL Import
```bash
curl https://example.com/api/me \
  -H "Cookie: session=abc123" \
  -H "Content-Type: application/json" \
  -d "{\"q\":\"test\"}"
```

### What Happens During the Scan
When a profile is selected, VulnPilot will:
- replay the imported authenticated requests
- merge them with normal crawler discovery
- mutate real parameters, headers, and bodies
- attach replayable evidence to findings

### Where Profiles Are Stored
Profiles are stored locally in a JSON file inside `backend/.data/attack_profiles.json`. No extra database setup is required.

---

## Headless CLI Usage

Manual repository or target audit:
```bash
cd backend
.venv\Scripts\python.exe cli.py --target "https://your-site.com" --fail-on "High" --output "report.md"
```

Apply security fixes to a local codebase:
```bash
cd backend
.venv\Scripts\python.exe cli.py --target "./" --apply-fix
```

---

## Architecture Stack
- Framework: FastAPI
- UI: Next.js
- Brain: Google Gemini / Groq
- Analysis: custom SAST + DAST + replayable request fuzzing

---

## Contributing
Secure code is a collective effort. Feel free to open issues or PRs to improve the scanner, remediation prompts, or fuzzing logic.
