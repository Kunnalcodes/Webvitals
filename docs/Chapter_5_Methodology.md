# Chapter 5: Methodology

The WebVitals platform employs a rigorous, multi-phased, and highly deterministic methodology to meticulously evaluate web targets. This structured approach ensures comprehensive coverage while virtually eliminating the false positives that plague traditional scanners.

## 5.1 Phase 1: Reconnaissance and Fingerprinting
The initial phase focuses on understanding the target's architecture and surface area without executing intrusive payloads.
- **Target Parsing & Normalization:** The system meticulously normalizes target URLs, resolves DNS structures, and establishes a baseline for connectivity and latency. This step ensures that subsequent probes are appropriately throttled and formatted.
- **Tech Stack Identification:** WebVitals performs deep analysis of HTTP response headers, meta tags, DOM structures, and exposed JavaScript variables. This allows the engine to accurately fingerprint underlying frameworks (e.g., React, Angular), Content Management Systems (e.g., WordPress, Ghost), and backend technologies (e.g., Node.js, Nginx), enabling highly targeted vulnerability scanning in subsequent phases.

## 5.2 Phase 2: Core Scanning & Diagnostics
This phase constitutes the bulk of the automated auditing process, leveraging the intelligence gathered during reconnaissance.
- **Security Analyzers:** The engine systematically probes for insecure HTTP methods (such as OPTIONS or TRACE), evaluates reverse proxy ingress and egress headers for misconfigurations, and rigorously assesses the strength of TLS/SSL configurations, DNSSEC integrity, and CAA record enforcement.
- **Configuration Auditing:** WebVitals conducts an exhaustive validation of critical security headers (including Content Security Policy [CSP], HTTP Strict Transport Security [HSTS], and X-Frame-Options), CORS policies to prevent cross-origin data leakage, and cookie security flags (HttpOnly, Secure, SameSite) to protect against session hijacking.
- **SEO & Performance Vitals:** Beyond security, the engine extracts and analyzes `robots.txt` files, XML sitemaps, and OpenGraph tags. It simulates browser rendering metrics to evaluate Google Lighthouse parameters, focusing on First Contentful Paint (FCP), Largest Contentful Paint (LCP), and Cumulative Layout Shift (CLS).

## 5.3 Phase 3: Deterministic Evidence & Verification
To ensure high fidelity in its reporting, WebVitals utilizes a deterministic verification engine.
- **False Positive Elimination:** Discovered vulnerabilities are not immediately flagged. Instead, they trigger secondary, highly targeted, and non-destructive probes designed to definitively confirm the vulnerability's existence. The resulting evidence is mathematically modeled and assigned a confidence score. Only issues that pass strict deterministic thresholds are forwarded to the reporting module, ensuring that development teams only spend time on genuine threats.

## 5.4 Phase 4: Threat Intelligence & AI Correlation
WebVitals enriches its local findings with global threat contexts and artificial intelligence.
- **External Correlation:** Discovered IP addresses, domains, and asset hashes are cross-referenced in real-time against industry-leading threat intelligence databases, primarily Google Safe Browsing and the VirusTotal API, to identify immediately compromised or historically malicious infrastructure.
- **AI Synthesis:** The deterministic evidence gathered is synthesized and securely fed into Google Gemini AI Studio. The LLM processes this context to generate bespoke, actionable remediation playbooks. These playbooks are explicitly tailored to the previously identified tech stack, providing developers with exact code snippets or configuration commands needed to resolve the issues.

## 5.5 Phase 5: Reporting & CI/CD Gating
The final phase focuses on delivering actionable intelligence to the end-users and integrating with automated pipelines.
- **Real-Time Telemetry:** Audit data is streamed asynchronously via WebSockets to the React-based frontend dashboard, providing users with immediate, interactive feedback during the scanning process.
- **Pipeline Integration:** Finalized results are serialized into multiple formats, including interactive visual dashboards, comprehensive PDF reports for executive stakeholders, and SARIF (Static Analysis Results Interchange Format) for deep CI/CD integration. This allows deployment pipelines to automatically fail or block deployments if specific, pre-defined risk thresholds are exceeded, enforcing a strict DevSecOps culture.
