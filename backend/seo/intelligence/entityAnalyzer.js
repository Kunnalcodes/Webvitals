/**
 * Entity & Brand Understanding Analyzer — WebVitals 2.0 GEO Intelligence
 *
 * Evaluates brand identity, organizational knowledge clarity, structured entity markup,
 * cross-channel consistency, and entity ambiguity for machine learning & generative AI systems.
 */

'use strict';

/**
 * Analyzes entity signals across metadata, schema, and page content.
 *
 * @param {Object} parsedData - Base metadata from htmlParser
 * @param {Object} contentData - Extracted content from contentExtractor
 * @param {string} url - Target URL
 * @returns {Object} Entity intelligence evaluation
 */
function analyzeEntityAndBrand(parsedData = {}, contentData = {}, url = '') {
  const jsonLd = parsedData.jsonLd || [];
  const og = parsedData.openGraph || {};
  const cleanText = contentData.cleanBodyText || '';
  const links = parsedData.links || [];

  // 1. Organization & Business Identity Extraction
  let organizationName = null;
  let organizationType = 'Organization';
  let logoUrl = null;
  let socialProfiles = [];
  let contactPoints = [];
  let founders = [];

  jsonLd.forEach(item => {
    const type = item['@type'];
    if (['Organization', 'Corporation', 'LocalBusiness', 'MedicalOrganization', 'NGO', 'SoftwareApplication', 'Store'].includes(type)) {
      if (item.name) organizationName = item.name;
      organizationType = type;
      if (item.logo) logoUrl = typeof item.logo === 'string' ? item.logo : item.logo.url;
      if (Array.isArray(item.sameAs)) socialProfiles.push(...item.sameAs);
      if (item.contactPoint) {
        contactPoints.push(Array.isArray(item.contactPoint) ? item.contactPoint : [item.contactPoint]);
      }
      if (item.founder) {
        const f = Array.isArray(item.founder) ? item.founder : [item.founder];
        founders.push(...f.map(p => typeof p === 'string' ? p : p.name));
      }
    }
  });

  // Fallback brand derivation from og:site_name, title, or hostname
  const siteName = og.site_name || null;
  let fallbackBrand = siteName;
  if (!fallbackBrand && parsedData.title) {
    const parts = parsedData.title.split(/[-–—|:]/);
    if (parts.length > 1) {
      fallbackBrand = parts[parts.length - 1].trim();
    }
  }
  if (!fallbackBrand && url) {
    try {
      const u = new URL(url);
      const hostParts = u.hostname.replace(/^www\./i, '').split('.');
      fallbackBrand = hostParts[0].charAt(0).toUpperCase() + hostParts[0].slice(1);
    } catch {}
  }

  const detectedBrandName = organizationName || fallbackBrand || 'Unspecified Brand';

  // 2. Discover External Social Entity Profiles from Links
  const socialDomains = ['twitter.com', 'x.com', 'linkedin.com', 'github.com', 'facebook.com', 'instagram.com', 'youtube.com'];
  links.forEach(l => {
    try {
      const u = new URL(l.url);
      if (socialDomains.some(d => u.hostname.includes(d))) {
        if (!socialProfiles.includes(l.url)) socialProfiles.push(l.url);
      }
    } catch {}
  });

  // 3. Category & Core Topic Modeling
  const detectedCategories = [];
  const lowerText = cleanText.toLowerCase();

  const CATEGORY_SIGNATURES = {
    'SaaS & Cloud Software': ['software', 'platform', 'api', 'dashboard', 'automation', 'cloud', 'developer', 'integrations'],
    'E-Commerce & Retail': ['cart', 'shop', 'checkout', 'pricing', 'store', 'shipping', 'order', 'products', 'currency'],
    'Cybersecurity & Network Defense': ['security', 'vulnerability', 'firewall', 'encryption', 'tls', 'penetration', 'soc', 'compliance'],
    'Healthcare & Medical': ['clinical', 'patient', 'doctor', 'treatment', 'healthcare', 'medical', 'therapy', 'diagnosis'],
    'Financial Services & Fintech': ['banking', 'investment', 'payments', 'crypto', 'loan', 'portfolio', 'interest', 'fintech'],
    'Media & Publishing': ['news', 'editorial', 'article', 'journal', 'magazine', 'author', 'press', 'coverage'],
    'Professional Services': ['consulting', 'advisory', 'client', 'agency', 'case study', 'strategy', 'solutions'],
  };

  Object.entries(CATEGORY_SIGNATURES).forEach(([category, terms]) => {
    const matches = terms.filter(t => lowerText.includes(t));
    if (matches.length >= 3) {
      detectedCategories.push({ category, matchCount: matches.length, matchedTerms: matches });
    }
  });

  const primaryCategory = detectedCategories.sort((a, b) => b.matchCount - a.matchCount)[0]?.category || 'General Web Property';

  // 4. Contact & Geographic Relevance
  const hasContactPage = links.some(l => /\b(contact|support|help)\b/i.test(l.url) || /\b(contact|support)\b/i.test(l.text));
  const hasAboutPage = links.some(l => /\b(about|company|team|who-we-are)\b/i.test(l.url) || /\b(about|our story)\b/i.test(l.text));
  const hasPhone = /\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/.test(cleanText);
  const hasEmail = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(cleanText);
  const hasPhysicalAddress = /(?:suite|street|st\.|ave|avenue|road|rd\.|blvd|box|zip|postal)\b/i.test(cleanText);

  // 5. Entity Ambiguity & Machine Understanding Evaluation
  const ambiguitySignals = [];
  const verifiedSignals = [];

  if (organizationName) {
    verifiedSignals.push(`Organization structured entity explicit via Schema: "${organizationName}"`);
  } else {
    ambiguitySignals.push('No Organization or LocalBusiness Schema. Brand name must be inferred heuristically.');
  }

  if (socialProfiles.length > 0) {
    verifiedSignals.push(`${socialProfiles.length} cross-platform social entity links discovered.`);
  } else {
    ambiguitySignals.push('No verified sameAs social profile links detected to establish knowledge graph authority.');
  }

  if (hasAboutPage) {
    verifiedSignals.push('Dedicated About / Company profile link discovered.');
  } else {
    ambiguitySignals.push('Missing explicit About/Company page link; origin identity is less transparent to AI engines.');
  }

  if (hasContactPage || hasEmail || hasPhone) {
    verifiedSignals.push('Verifiable customer contact channels present.');
  } else {
    ambiguitySignals.push('No clear contact page or direct email/phone signals detected.');
  }

  // Clarity score (0-100)
  let clarityScore = 40;
  if (organizationName) clarityScore += 25;
  if (socialProfiles.length >= 2) clarityScore += 15;
  if (hasAboutPage) clarityScore += 10;
  if (hasContactPage) clarityScore += 10;
  clarityScore = Math.min(100, clarityScore);

  const clarityRating = clarityScore >= 80 ? 'High' : clarityScore >= 60 ? 'Moderate' : clarityScore >= 40 ? 'Ambiguous' : 'Unidentified';

  return {
    brandName: detectedBrandName,
    organizationType,
    primaryCategory,
    detectedCategories: detectedCategories.map(c => c.category),
    clarityScore,
    clarityRating,
    logoUrl,
    socialProfiles,
    contactInfo: {
      hasContactPage,
      hasAboutPage,
      hasPhone,
      hasEmail,
      hasPhysicalAddress,
    },
    authorship: contentData.authorship || {},
    verifiedSignals,
    ambiguitySignals,
    machineSummary: `Entity recognized as "${detectedBrandName}" operating in the "${primaryCategory}" category with ${clarityRating.toLowerCase()} entity clarity for knowledge graph indexing.`,
  };
}

module.exports = {
  analyzeEntityAndBrand,
};
