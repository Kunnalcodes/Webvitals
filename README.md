# 🛡️ WebVitals — Web Security, SEO & Tech Stack Intelligence Platform

> **Enterprise-grade Web Security Auditing, Technical SEO Health, Grounded AI Reasoning & Cyber Threat Intelligence Engine**
> 
> *Created & Maintained by **Kunal Sharma***

WebVitals is a comprehensive full-stack security and web intelligence platform designed to audit web applications, eliminate false positives through deterministic evidence verification, probe HTTP methods and access control headers, analyze on-page technical SEO & Core Web Vitals, correlate real-time threat intelligence (Google Cloud, VirusTotal, NIST NVD), and generate actionable remediation playbooks powered by Google Gemini AI.

---

## 🌟 Architecture & Key Capabilities

- **Zero-Dependency Core Backend:** Native Node.js HTTP/HTTPS implementation with zero runtime npm dependencies for sub-second execution speed, minimal memory footprint, and hardened security.
- **12+ Core Security Audit Channels:** Headers (CSP, HSTS, XFO, XCTO), TLS 1.3/SSL, DNSSEC & CAA, CORS, Cookie Security, Sensitive Files & Repo Leaks (.git, .env), Access Control & Reverse Proxy Directives, Tech Stack CVEs, Phishing & Malware Heuristics, Information Disclosure, Open Redirects.
- **Access Control & Reverse Proxy Diagnostic Engine:** Probes HTTP methods (`OPTIONS`, `HEAD`, `TRACE`, `PUT`, `DELETE`) for XST risk and tests reverse proxy ingress headers (`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-For`, `X-Custom-IP-Authorization`) to detect route overrides and ACL bypass vulnerabilities.
- **Complete Technical SEO & Core Web Vitals:** Integrated Google Lighthouse metrics, SERP snippet simulation, OpenGraph / Twitter Card validation, robots.txt, XML sitemap verification, and Core Web Vitals (FCP, LCP, TBT, CLS).
- **Google Cloud & Threat Intel Ecosystem:**
  - **Google Gemini AI Studio / Vertex AI:** Grounded security reasoning, executive threat summaries, interactive SecOps AI advisor.
  - **Google Safe Browsing v4 & Web Risk:** Real-time detection of malware, phishing, and social engineering domains.
  - **Google PageSpeed Insights & CrUX:** Real-world Chrome User Experience metrics and Lighthouse diagnostics.
  - **Google Public DNS-over-HTTPS (DoH):** Cryptographic DNSSEC (`AD=true`) and Certificate Authority Authorization (`CAA`) validation.
  - **VirusTotal API v3:** 70+ vendor multi-engine malware and reputation feeds.
- **Interactive Visualizations & Multi-Format Exports:**
  - Interactive radar risk charts, severity distributions, and historical timeline trends.
  - Multi-page branded PDF reports, SARIF (GitHub Advanced Security format), and Markdown CI summaries.
  - DevSecOps CI/CD Gate CLI status and threshold scoring (`/api/scan/gate`).

---

## 🚀 Quick Start (Development)

### 1. Run Both Frontend & Backend (One Single Command)
```bash
npm run dev
```
- **Frontend Web UI:** `http://localhost:5173`
- **Backend API Server:** `http://localhost:8888`
- **Live WebSocket:** `ws://localhost:8888/ws`

### 2. Run Test Suite
```bash
npm test
```
*Executes all 177 unit and integration tests across 43 test suites with 0 external dependencies.*

---

## 🚢 Production Deployment

WebVitals is fully packaged for one-click production deployment across containerized and cloud platforms.

### Option A: Direct Node.js Production Server
```bash
# 1. Build the production frontend bundle
npm run build

# 2. Start the unified full-stack server
npm start
```
*The backend server will automatically serve the built frontend (`frontend/dist/`) and all API routes on `PORT` (default `8888`).*

### Option B: Docker Container
```bash
# Build and run the single lightweight container
docker build -t webvitals .
docker run -p 8888:8888 webvitals
```

### Option C: Docker Compose
```bash
docker-compose up --build -d
```

### Option D: Render.com / Railway / Cloud Run
- **Build Command:** `npm run build`
- **Start Command:** `npm start`
- **Environment Variables:**
  - `NODE_ENV=production`
  - `PORT=10000` (or platform default)
  - `AI_ENABLED=true`
  - `GOOGLE_API_KEY=your_key`

---

## 📂 Project Structure

```
WebVitals/
├── backend/                  # High-performance zero-dep Node.js engine
│   ├── ai/                   # Gemini AI client, prompts, and validator
│   ├── analyzers/            # 12+ deterministic security & access analyzers
│   │   ├── httpVerbAnalyzer.js    # HTTP method diagnostics (OPTIONS, TRACE, etc.)
│   │   ├── proxyHeaderAnalyzer.js # Reverse proxy header ACL probes
│   │   └── ...
│   ├── evidence/             # Phase 3 verified evidence model & confidence engine
│   ├── executive/            # Executive summary generator
│   ├── exports/              # PDF, SARIF, Markdown export engines
│   ├── remediation/          # Multi-stack fix generators (Nginx, Apache, Next.js, etc.)
│   ├── scan/                 # Parallel scan orchestrator & cache
│   ├── seo/                  # Lighthouse & Google PageSpeed auditor
│   ├── services/             # Unified threat intelligence (Safe Browsing, VT, DoH)
│   ├── storage/              # In-memory & persistent scan repository
│   ├── tests/                # 177 test cases across Phase 1-4
│   └── websocket/            # Real-time WebSocket scan telemetry
├── frontend/                 # Modern React + Vite + Tailwind + Lucide UI
│   ├── src/
│   │   ├── components/       # Scanners, Access Control Tabs, AI Chat, Tech Stack, SEO
│   │   ├── hooks/            # Scan & benchmark state management
│   │   ├── services/         # API & WebSocket client
│   │   └── utils/            # PDF export & report generators
│   └── vite.config.js        # Local proxy to backend (Port 8888)
├── extension/                # Chrome / Edge / Brave Manifest V3 Extension
├── scripts/                  # Unified start-dev orchestrator
├── Dockerfile                # Multi-stage production container definition
├── docker-compose.yml        # Multi-container orchestration
├── render.yaml               # Render.com blueprint deployment config
├── vercel.json               # Vercel deployment rewrite rules
├── package.json              # Root workspace manager & scripts
└── README.md                 # Complete documentation
```

---

## 📜 License & Credits

- **Author:** Kunal Sharma
- **License:** MIT
- **Disclaimer:** This software is developed for security evaluation, authorized pentesting, and educational analysis.
