# 🛸 VulnPilot

> **The world's first fully automated, context-aware offensive security platform.**

VulnPilot is an autonomous security assistant designed to **find, verify, fix, and explain** vulnerabilities in real-time. By bridging the gap between static analysis (**SAST**) and dynamic testing (**DAST**), VulnPilot provides a seamless workflow that moves from discovery to remediation in seconds.

[![Status](https://img.shields.io/badge/Status-Active-emerald?style=for-the-badge)]()
[![Backend](https://img.shields.io/badge/Backend-FastAPI-teal?style=for-the-badge)]()
[![Frontend](https://img.shields.io/badge/Frontend-Next.js-white?style=for-the-badge)]()
[![Engine](https://img.shields.io/badge/Engine-Hybrid_AI-blueviolet?style=for-the-badge)]()

---

## ⚡ Core Superpowers

### 🏟️ The War Room
A high-fidelity cockpit for security researchers. Monitor your scan's progress via real-time WebSocket streams.
- **Phased Intelligence**: `init` → `recon` → `sca` → `sast` → `secrets` → `logic` → `dast` → `analysis`.
- **Live Finding Stream**: Instant alerts with AI-generated explanations and replay evidence.

### 🛠️ The Active Fixer
Don't just find bugs—obliterate them. One-click security remediation.
- **Autonomous Refactoring**: AI-powered code transformation for local source files.
- **Secure Blueprints**: Get developer-facing remediation steps and secure code snippets instantly.

### 🔑 AI-Assisted Secrets Detection
Sophisticated leak scanning that goes beyond regex.
- **Intelligent Prioritization**: Scans sensitive targets (`.env`, `secrets.yaml`, `config.json`) first to minimize risk exposure.
- **False Positive Filtering**: AI validates the context of discovered strings to reduce noise.

### 🎭 Authenticated Attack Profiles
Audit deeper than ever by importing real browser traffic.
- **HAR & cURL Import**: Learn complex workflows from your browser session.
- **Mutation Engine**: Replays and mutates authenticated requests to find IDORs and logic flaws.

### 🌪️ Deep Offensive Engine
- **Bespoke AI Fuzzing**: Contextual payloads generated based on discovered parameters and sinks.
- **Taint-Chasing SAST**: Traces user input from entry point to dangerous sink across multiple files.
- **Native SCA**: AI-assisted dependency analysis to catch vulnerable libraries before they bite.

---

## 🚀 Quick Start

### 1. Initialize the Cockpit
```bash
git clone https://github.com/Abmarne/VulnPilot.git
cd VulnPilot
```

### 2. Configure Brains
Create a `.env` file in `backend/`:
```env
GOOGLE_API_KEY=your_gemini_key_here
GROQ_API_KEY=your_groq_key_here
# Optional: ANTHROPIC_API_KEY, OPENAI_API_KEY
```

### 3. Launch the Engines
**Backend:**
```bash
cd backend
python -m venv .venv
# Windows
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

**Frontend:**
```bash
cd ../frontend
npm install
npm run dev
```

---

## 📖 Using Authenticated Profiles

Authenticated profiles allow VulnPilot to audit dashboards, internal APIs, and logged-in administrative flows.

1.  **Export HAR**: Open DevTools → Network Tab → Right-click → `Save all as HAR with content`.
2.  **Import**: Paste the HAR file or a single cURL into the VulnPilot dashboard.
3.  **Audit**: Select the profile and Launch. VulnPilot will automatically merge these requests into its attack surface Map.

---

## 🖥️ Headless CLI Usage

For automation and CI/CD pipelines:

```bash
# Full Target Audit
python cli.py --target "https://your-site.com" --fail-on "High" --output "report.md"

# Apply Auto-Remediation to Local Code
python cli.py --target "./workspace" --apply-fix
```

---

## 🏗️ Architecture Stack

VulnPilot is built on a mission-critical stack designed for speed and intelligence.

- **Orchestration**: FastAPI (Python)
- **Interface**: Next.js 14 (React)
- **Brains**: Multi-model support (Gemini 2.0 Flash, Groq/Llama-3, Claude 3.5, GPT-4o)
- **Analysis Ecosystem**: 
  - **Hybrid SAST**: Taint-chasing logic with intelligent file prioritization.
  - **Contextual DAST**: AI-guided fuzzing based on discovered API schemas.
  - **Secrets Scanner**: Deep scan for credentials, tokens, and private keys.
  - **Native SCA**: Automated manifest analysis.

---

## 🤝 Contributing

We believe security is a collective effort. If you have any ideas for new fuzzing payloads, remediation prompts, or engine optimizations, feel free to open a PR!

**VulnPilot** — *Scan smarter, fix faster, sleep better.*
