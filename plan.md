# VulnPilot: Black-Box DAST Orchestrator Plan

## 1. Executive Summary
VulnPilot is an intelligent, automation-driven open-source web application designed to perform Dynamic Application Security Testing (DAST) on web applications. Operating entirely as a "black-box" analyst, it crawles running Web Apps without source code access, tests endpoints using benign payloads, and leverages Google Gemini to interpret server anomalies. 

The ultimate goal is to provide developers with automatically generated, safe manual verification steps (Proofs of Concept) to test their own applications.

## 2. Core Features & Scope

### 2.1 Reconnaissance & Fuzzing (The Outer Layer)
- **Intelligent Crawler:** A Python-based agent that navigates a target URL, discovering forms, parameters, hidden endpoints, and API routes.
- **Session Authentication:** The crawler accepts a valid session cookie or token from the user, allowing it to crawl and fuzz authenticated areas of the target app.
- **Benign Fuzzing Engine:** The tool sends basic, non-destructive payloads (e.g., `' OR 1=1`, extremely long strings, `<script>alert(1)</script>`) to trigger errors or unexpected behavior.

### 2.2 The "LLM Analyst" (The Inner Layer)
- **Anomaly Detection:** Any unexpected HTTP response (Internal Server Errors, database stack traces, reflected input) is caught.
- **Gemini Contextualization:** Gemini reads the anomalous HTTP Request/Response pairs and deduces the probability of a vulnerability (e.g., SQLi, XSS, SSRF).

### 2.3 Safe Proof & Remediation
- **Manual Verification Generation:** Gemini generates a "Safe PoC" — step-by-step instructions or non-harmful scripts (like popping an alert box or inducing a sleep query) that the user can run manually to safely confirm the vulnerability.
- **Remediation Advice:** Theoretical explanation and code-level fixes are provided to secure the vulnerability.

## 3. Architecture & Tech Stack

### 3.1 Frontend (The Analyst Dashboard)
- **Framework:** Next.js (React) + TypeScript.
- **Styling:** Tailwind CSS.
- **Focus:** A premium, dark-mode user interface that displays the live crawler log, highlights vulnerable endpoints, and presents the Gemini PoC guides cleanly.

### 3.2 Backend (The Fuzzer & Orchestrator)
- **Framework:** Python / FastAPI.
- **Tools:** `requests` / `BeautifulSoup` (for crawling), integrated with the Google Gemini API.
- **Data Storage:** SQLite (for local portability) or a simple JSON document store.

## 4. Implementation Phases

- **Phase 1: MVP Setup & The Foundation**
  - Initialize the Next.js Frontend and Python FastAPI Backend.
  - Implement the fundamental target input, session cookie injection, and base crawler logic.
- **Phase 2: The Fuzzing Engine**
  - Build the async payload delivery system to test inputs safely without bringing down the target server.
- **Phase 3: Gemini Integration & Dashboard**
  - Integrate the Google Gemini API, construct the prompt templates for analyzing raw HTTP traffic, and display the resulting PoCs on the frontend.

## 5. Future Scope (Maximum Coverage / Hybrid Mode)
*Note: We have elected to stick with the Option A "Black-Box" approach for the initial MVP to simulate an external hacker. However, to achieve maximum vulnerability coverage in the future, the architecture will support a "Grey-Box" hybrid mode.*

- **Phase 4: Passive Analysis Integration (Grey-Box)**
  - Integrate Semgrep and Trivy to allow users to attach their source-code repositories. The LLM will then synthesize the external DAST fuzzing anomalies with the internal SAST vulnerability reports to catch hardcoded secrets and deep backend architectural flaws that the Black-Box crawler cannot reach.
