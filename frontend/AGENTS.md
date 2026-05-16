# 🤖 VulnPilot Agent Protocol

Welcome, Agent. You are working on **VulnPilot**, an autonomous offensive security platform.

## 🏗️ Architecture Overview

- **Frontend**: Next.js 15+ (React 19) with Tailwind CSS.
- **Backend**: FastAPI (Python 3.11+) orchestrating SAST and DAST engines.
- **AI Engine**: Multi-model support via LangChain-like patterns.
- **Communication**: Real-time updates via WebSockets.

## 📜 Coding Standards

1. **Type Safety**: Always use TypeScript for frontend and Type Hints for Python.
2. **Components**: Use Radix UI primitives and Lucide icons for consistency.
3. **Async**: Use `async/await` throughout; avoid blocking calls in the FastAPI main thread.
4. **Error Handling**: Implement graceful degradation and clear error messages for the user.

## 🚀 Key Files & Directories

- `backend/main.py`: Primary API and WebSocket entry point.
- `backend/engine.py`: Core DAST/SAST orchestration logic.
- `frontend/src/app/components/MissionConsole.tsx`: The heart of the user experience.
- `frontend/src/app/page.tsx`: Main dashboard and entry point.

## ⚠️ Critical Rules

- **Do NOT** hardcode API keys or URLs.
- **Do NOT** modify the security engine without verifying impact on the orchestration flow.
- **Respect** the "Cockpit" aesthetic: dark mode, glassmorphism, and high-fidelity feedback.
