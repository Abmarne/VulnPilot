# 🛡️ VulnPilot

![VulnPilot Logo](file:///C:/Users/Abhiraj/.gemini/antigravity/brain/4170566f-c42b-479a-b23f-b086fe977bad/vulnpilot_logo_1775565443642.png)

> **The World's First Fully-Automated 'Active Security' Platform.** 🚀

VulnPilot isn't just a scanner. It's a context-aware security engineer that **Finds, Verifies, Fixes, and Blocks** vulnerabilities in real-time. Designed for developers and SOC teams, it bridges the gap between vulnerability discovery and secure code remediation.

---

## 🌟 Core Superpowers

### 🎮 The War Room (Real-time Dashboard)
A high-contrast, WebSocket-driven dashboard that streams scan logs and findings in real-time.
- **5-Stage Live Pipeline**: Tracking progress from Init → Recon → SAST → Fuzzing → Analysis.
- **Micro-animations & Alerts**: High-confidence "Verified Proof" badges for proven bugs.

### 🛡️ The Active Fixer (Auto-Remediation)
Turn findings into secure code with one click.
- **AI-Powered Refactoring**: Gemini 2.0 Flash rewrites entire source files to remove vulnerabilities (SQLi, XSS, etc.) while preserving all application logic.
- **Secure Implementation Snippets**: Instant, high-fidelity code patches ready for copy-paste or automatic applying.

### 🕵️‍♂️ Hybrid Context-Aware Engine
- **Taint-Chasing SAST**: Multi-file data flow analysis to reduce false positives.
- **Double-Blind Fuzzing**: Mathematical verification of vulnerabilities via logical DAST testing.
- **Ghost API Recon**: Reverse-engineers client-side JS to find hidden and undocumented endpoints.

### ⛓️ CI/CD Security Gate
A headless CLI (`cli.py`) that permits fully automated repo auditing in GitHub Actions.
- **Exit Code Enforcement**: Fails builds if High/Critical risks are detected.
- **Automatic PR Commenting**: Posts full security reports directly as PR comments.

---

## 🚀 Getting Started

### 1️⃣ Clone and Prepare Env
```bash
git clone https://github.com/Abmarne/VulnPilot.git
cd VulnPilot/backend
```
Create a `.env` file in the `backend/` directory:
```env
GOOGLE_API_KEY=your_gemini_key_here
GROQ_API_KEY=your_groq_key_here
```

### 2️⃣ Install Dependencies
```bash
# Backend (Python 3.10+)
pip install -r requirements.txt

# Frontend (Next.js)
cd ../frontend
npm install
```

### 3️⃣ Launch the War Room
```bash
# Start Backend
python backend/main.py

# Start Frontend
npm run dev
```
Navigate to `http://localhost:3000` to start your first live scan.

---

## 🤖 Headless CLI Usage

For CI/CD pipelines, use the headless agent:
```bash
python backend/cli.py --target "https://your-site.com" --fail-on "High" --output "report.md"
```

To automatically apply security fixes to your local codebase:
```bash
python backend/cli.py --target "./" --apply-fix
```

---

## 🏗️ Architecture Stack
- **Framework**: FastAPI (Orchestration & WebSockets)
- **UI**: Next.js (Tailwind CSS, Real-time React Hooks)
- **Brain**: Google Gemini 2.0 Flash / Llama 3.3 (Logic & Remediation)
- **Analysis**: Custom-built Taint Analysis Engine & DAST Fuzzer

---

## 🤝 Contributing
Secure code is a collective effort. Feel free to open issues or PRs to improve the remediation prompts or the fuzzer logic!

---

*“Don’t just find bugs. Neutralize them with VulnPilot.”* 🛡️
