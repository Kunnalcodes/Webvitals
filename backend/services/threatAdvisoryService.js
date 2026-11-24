/**
 * Technology Threat Advisory & CVE Intelligence Engine — Phase 4
 * WebVitals
 *
 * Correlates detected technology stacks with known vulnerability advisories,
 * CVSS v3.1 severity scores, attack vectors, and actionable mitigation guidance.
 */

'use strict';

const CVE_KNOWLEDGE_BASE = [
  {
    tech: 'Next.js',
    cves: [
      {
        id: 'CVE-2024-34351',
        title: 'Server-Side Request Forgery (SSRF) in Next.js Server Actions',
        severity: 'HIGH',
        cvss: 7.5,
        affectedVersions: '>= 13.4.0, < 14.1.1',
        vector: 'Network / Unauthenticated',
        description: 'Server Actions with redirect logic can be coerced by an attacker supplying a spoofed Host header to cause the server to fetch and forward internal resources.',
        mitigation: 'Upgrade Next.js to version 14.1.1 or later. Validate incoming Host and X-Forwarded-Host headers at the edge reverse proxy.',
        reference: 'https://nvd.nist.gov/vuln/detail/CVE-2024-34351',
      },
      {
        id: 'CVE-2023-48309',
        title: 'Cache Poisoning & Stale Header Reflection in Image Optimizer',
        severity: 'MEDIUM',
        cvss: 6.5,
        affectedVersions: '>= 12.0.0, < 13.5.1',
        vector: 'Network / CDN Cache',
        description: 'Next.js image optimization endpoint could be exploited under certain CDN configurations to poison cached static assets.',
        mitigation: 'Update to Next.js 13.5.1+ and enforce explicit remotePatterns in next.config.js.',
        reference: 'https://nvd.nist.gov/vuln/detail/CVE-2023-48309',
      },
    ],
  },
  {
    tech: 'WordPress',
    cves: [
      {
        id: 'CVE-2024-31210',
        title: 'Arbitrary File Deletion / Overwrite in Core Media Uploader',
        severity: 'HIGH',
        cvss: 8.8,
        affectedVersions: '< 6.5.2',
        vector: 'Authenticated / Media Subsystem',
        description: 'A flaw in path sanitization allows authenticated users with upload privileges to delete arbitrary files on the hosting server.',
        mitigation: 'Update WordPress core immediately to version 6.5.2 or later. Restrict contributor upload capabilities.',
        reference: 'https://nvd.nist.gov/vuln/detail/CVE-2024-31210',
      },
      {
        id: 'CVE-2023-38000',
        title: 'XML-RPC Amplification & Brute-Force Vulnerability',
        severity: 'MEDIUM',
        cvss: 5.3,
        affectedVersions: 'All versions with xmlrpc.php enabled',
        vector: 'Network / Unauthenticated',
        description: 'The legacy XML-RPC interface allows pingback amplification DDoS attacks and rapid multicall credential brute-forcing.',
        mitigation: 'Disable xmlrpc.php at the web server (Nginx/Apache) or via security plugins if mobile app sync is not required.',
        reference: 'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2023-38000',
      },
    ],
  },
  {
    tech: 'Apache',
    cves: [
      {
        id: 'CVE-2021-41773',
        title: 'Path Traversal and Remote Code Execution in Apache HTTP Server',
        severity: 'CRITICAL',
        cvss: 9.8,
        affectedVersions: 'Apache 2.4.49, 2.4.50',
        vector: 'Network / Unauthenticated',
        description: 'Flaw in path normalization logic allows attackers to map URLs to files outside the expected document root or execute arbitrary CGI binaries.',
        mitigation: 'Ensure Apache HTTP Server is updated to version 2.4.51 or higher. Verify "Require all denied" on filesystem root in httpd.conf.',
        reference: 'https://nvd.nist.gov/vuln/detail/CVE-2021-41773',
      },
      {
        id: 'CVE-2023-25690',
        title: 'HTTP Request Smuggling via mod_proxy Forwarding',
        severity: 'HIGH',
        cvss: 8.6,
        affectedVersions: 'Apache 2.4.0 through 2.4.55',
        vector: 'Network / Reverse Proxy',
        description: 'Specific mod_proxy configurations allow HTTP request smuggling between client and upstream backend servers via crafted split requests.',
        mitigation: 'Upgrade to Apache 2.4.56+. Avoid using RewriteRule flags with unencoded client input in proxy targets.',
        reference: 'https://nvd.nist.gov/vuln/detail/CVE-2023-25690',
      },
    ],
  },
  {
    tech: 'Nginx',
    cves: [
      {
        id: 'CVE-2021-23017',
        title: '1-byte Memory Overwrite in DNS Resolver',
        severity: 'HIGH',
        cvss: 8.1,
        affectedVersions: 'Nginx 0.6.18 through 1.20.0',
        vector: 'Network / DNS Response',
        description: 'A security issue in the Nginx DNS resolver enables a 1-byte memory overwrite when processing crafted UDP DNS responses, leading to worker crash or arbitrary code execution.',
        mitigation: 'Upgrade to Nginx 1.20.1+, 1.21.0+, or mainstream stable releases.',
        reference: 'https://nvd.nist.gov/vuln/detail/CVE-2021-23017',
      },
      {
        id: 'CVE-2022-41741',
        title: 'Memory Corruption in Nginx mp4 Module',
        severity: 'MEDIUM',
        cvss: 7.1,
        affectedVersions: 'Nginx 1.1.3 through 1.23.1',
        vector: 'Network / Media Streaming',
        description: 'An integer overflow in ngx_http_mp4_module might cause worker process termination or potential code execution via a crafted MP4 file.',
        mitigation: 'Upgrade Nginx to version 1.23.2+ or 1.22.1+. Disable mp4 module if video streaming is not served.',
        reference: 'https://nvd.nist.gov/vuln/detail/CVE-2022-41741',
      },
    ],
  },
  {
    tech: 'Express',
    cves: [
      {
        id: 'CVE-2024-29041',
        title: 'Open Redirect & SSRF via Incomplete URL Validation in Express Router',
        severity: 'MEDIUM',
        cvss: 6.1,
        affectedVersions: 'Express < 4.19.2',
        vector: 'Network / Query Parsing',
        description: 'Express.js res.location() and res.redirect() could accept malicious user-supplied protocol characters leading to client redirection bypass.',
        mitigation: 'Upgrade express to 4.19.2 or 5.0.0+. Implement strict URL allowlisting on redirects.',
        reference: 'https://nvd.nist.gov/vuln/detail/CVE-2024-29041',
      },
      {
        id: 'CVE-2022-24999',
        title: 'Prototype Pollution / DoS in qs Query Parser',
        severity: 'HIGH',
        cvss: 7.5,
        affectedVersions: 'qs < 6.9.7 (bundled in older Express)',
        vector: 'Network / Query Strings',
        description: 'Deeply nested query parameters could cause denial of service or prototype pollution in application runtime.',
        mitigation: 'Update dependencies and run npm audit fix. Set app.set("query parser", "simple") if deep nesting is not required.',
        reference: 'https://nvd.nist.gov/vuln/detail/CVE-2022-24999',
      },
    ],
  },
  {
    tech: 'Spring Boot / Java',
    cves: [
      {
        id: 'CVE-2022-22965',
        title: 'Spring4Shell: Remote Code Execution in Spring Framework',
        severity: 'CRITICAL',
        cvss: 9.8,
        affectedVersions: 'Spring Framework 5.3.0 to 5.3.17, 5.2.0 to 5.2.19 on JDK 9+',
        vector: 'Network / DataBinder Access',
        description: 'Class loader manipulation via DataBinder allows unauthenticated remote attackers to write JSP web shells to disk.',
        mitigation: 'Upgrade to Spring Framework 5.3.18+ / Spring Boot 2.6.6+. Ensure Tomcat access logs cannot be manipulated by request parameters.',
        reference: 'https://nvd.nist.gov/vuln/detail/CVE-2022-22965',
      },
    ],
  },
  {
    tech: 'Laravel / PHP',
    cves: [
      {
        id: 'CVE-2021-3129',
        title: 'Remote Code Execution in Ignition Error Page',
        severity: 'CRITICAL',
        cvss: 9.8,
        affectedVersions: 'facade/ignition < 2.5.2 (Laravel <= 8.4.2)',
        vector: 'Network / Unauthenticated (when debug is true)',
        description: 'Ignition error page provides an insecure execute-solution route that executes arbitrary PHAR deserialization payloads.',
        mitigation: 'Set APP_DEBUG=false in production .env. Update facade/ignition to 2.5.2+ or spatie/laravel-ignition.',
        reference: 'https://nvd.nist.gov/vuln/detail/CVE-2021-3129',
      },
    ],
  },
];

/**
 * Correlates detected technologies with known CVE advisories.
 *
 * @param {Array<{ name: string }>} detectedTech
 * @returns {Array<object>}
 */
function correlateThreatAdvisories(detectedTech = []) {
  const advisories = [];
  const techNames = (detectedTech || []).map((t) => (t.name || '').toLowerCase());

  for (const entry of CVE_KNOWLEDGE_BASE) {
    const targetKey = entry.tech.toLowerCase();
    const isMatched = techNames.some((name) => name.includes(targetKey) || targetKey.includes(name));

    if (isMatched) {
      for (const cve of entry.cves) {
        advisories.push({
          techName: entry.tech,
          ...cve,
        });
      }
    }
  }

  // Sort by CVSS score descending
  return advisories.sort((a, b) => (b.cvss || 0) - (a.cvss || 0));
}

module.exports = {
  CVE_KNOWLEDGE_BASE,
  correlateThreatAdvisories,
};
