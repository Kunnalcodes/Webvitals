# Chapter 1: Introduction

## 1.1 Project Overview
**WebVitals** (developed under Project WebVitals) is an enterprise-grade full-stack security and web intelligence platform. It is engineered to audit web applications, analyze technical SEO health, and evaluate Core Web Vitals simultaneously. The platform eliminates false positives by applying deterministic evidence verification, probing HTTP methods and access control headers, and correlating real-time threat intelligence from providers such as Google Cloud, VirusTotal, and NIST NVD. Actionable remediation playbooks are generated dynamically via Google Gemini AI.

## 1.2 Organization
This project is organized into modular subsystems:
- **Backend:** A high-performance, zero-dependency Node.js engine encompassing analyzers, threat intelligence services, Gemini AI validation, and parallel scan orchestration.
- **Frontend:** A modern, interactive UI built with React, Vite, and Tailwind CSS, featuring interactive risk radar charts, timeline trends, and real-time WebSocket telemetry.
- **Reporting & Export:** Built-in capabilities to generate PDF reports, SARIF formats for GitHub Advanced Security, and Markdown summaries for CI/CD integration.

## 1.3 Area of Computer Science
This project spans several critical domains within Computer Science:
- **Cybersecurity & Threat Intelligence:** Vulnerability scanning, access control testing, and malware heuristics.
- **Artificial Intelligence & Machine Learning:** Leveraging LLMs (Google Gemini) for grounded security reasoning and SecOps advisory.
- **Web Engineering & Performance Optimization:** Technical SEO, Core Web Vitals, and real-time networking using WebSockets.
- **DevSecOps:** Continuous integration and deployment pipeline security gating.

## 1.4 Hardware and Software Requirements

### 1.4.1 Hardware Requirements
- **Processor:** Multi-core CPU (Intel i5/AMD Ryzen 5 or higher recommended)
- **RAM:** Minimum 4GB (8GB recommended for parallel analysis)
- **Storage:** 500MB free disk space for local installation (SSD preferred)
- **Network:** Active high-speed internet connection for API interactions and threat feed correlation.

### 1.4.2 Software Requirements
- **Operating System:** Windows 10/11, macOS, or Linux (Ubuntu/Debian)
- **Runtime:** Node.js (v18.x or higher)
- **Package Manager:** npm (v9.x or higher)
- **Web Browser:** Modern Chromium-based browser (Chrome, Edge, Brave) or Firefox
- **Containerization (Optional):** Docker and Docker Compose for containerized deployment.

### 1.4.3 Development Tools & Platform Compatibility
While the WebVitals platform is universally accessible via standard web browsers, its development and deployment require specific tools and utilities. These tools are industry-standard, widely supported, and have comprehensive documentation available:

**Code Editor/IDE:**
- **Visual Studio Code (VS Code)** - Recommended for its lightweight nature, extensive extension ecosystem, and built-in terminal.
- **WebStorm/IntelliJ IDEA** - Full-featured IDE for professional development with advanced debugging tools.
- **Sublime Text** - Lightweight alternative with extensive plugin support.

**Version Control:**
- **Git** (version 2.30 or higher) - For source code management and version control.
- **GitHub, GitLab, or Bitbucket** - Cloud-based repository hosting platforms for collaboration.

**API Testing Tools:**
- **Postman** - Comprehensive API testing and documentation tool with request collections for validating the scanning endpoints.
- **Insomnia** - Lightweight alternative with a simplified interface for REST API testing.

**Build and Package Managers:**
- **npm (Node Package Manager)** - Bundled with Node.js for managing JavaScript dependencies.
- **Vite** - Next-generation frontend tooling used for building the React application.

**Platform Compatibility:**
- **Responsive Web Design** - The React frontend, styled with Tailwind CSS, is fully responsive and compatible with desktop, tablet, and mobile devices.
- **Cross-platform Backend** - The zero-dependency Node.js backend runs identically on Windows, macOS, and Linux.
- **Docker Support** - Containerization allows for seamless and consistent deployment across different cloud environments (Render, Vercel, Railway, Cloud Run).
