# 🛠️ VulnPilot Development Guide

## 🚀 Common Commands

### Frontend
- **Dev Server**: `npm run dev`
- **Build**: `npm run build`
- **Lint**: `npm run lint`

### Backend
- **Run Server**: `python main.py`
- **Install Deps**: `pip install -r requirements.txt`
- **Type Check**: `mypy .` (if configured)

## 📜 Project Conventions
- **Naming**: Use PascalCase for React components, camelCase for variables/functions.
- **Styling**: Tailwind CSS for all UI elements.
- **Backend API**: REST for static data, WebSockets for mission logs.
- **State**: Use React `useState`/`useEffect` for local UI state; avoid heavy global state unless necessary.
