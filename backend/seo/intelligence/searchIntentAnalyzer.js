/**
 * Search Intent Classifier & Intent Mismatch Detector — WebVitals 2.0 SEO Intelligence
 *
 * Classifies search intent into Informational, Navigational, Commercial Investigation,
 * Transactional, and Local Intent, and flags structural mismatches between content and query expectations.
 */

'use strict';

/**
 * Classifies search intent and evaluates user satisfaction alignment.
 *
 * @param {Object} parsedData
 * @param {Object} contentData
 * @param {string} url
 * @returns {Object} Search intent classification & mismatch analysis
 */
function classifySearchIntent(parsedData = {}, contentData = {}, url = '') {
  const title = (parsedData.title || '').toLowerCase();
  const desc = (parsedData.metaDescription || '').toLowerCase();
  const body = (contentData.cleanBodyText || '').toLowerCase();
  const h1 = (contentData.headingsTree || []).filter(h => h.level === 1).map(h => h.text.toLowerCase()).join(' ');

  // Signal detection dictionaries
  const INTENT_SIGNALS = {
    transactional: ['buy', 'pricing', 'order', 'checkout', 'sign up', 'register', 'subscribe', 'download', 'start trial', 'free trial', 'get started', 'hire', 'quote'],
    commercial: ['best', 'vs', 'comparison', 'review', 'alternatives', 'top', 'features', 'benefits', 'pros and cons', 'pricing plans', 'tier'],
    informational: ['what is', 'how to', 'guide', 'tutorial', 'tips', 'learn', 'explained', 'why', 'overview', 'documentation', 'docs', 'manual'],
    navigational: ['login', 'signin', 'portal', 'account', 'dashboard', 'official site', 'home', 'about us', 'contact'],
    local: ['near me', 'location', 'hours', 'directions', 'office in', 'city', 'phone', 'address', 'branch'],
  };

  const scores = {
    transactional: 0,
    commercial: 0,
    informational: 0,
    navigational: 0,
    local: 0,
  };

  // Score based on title (high weight), headings (medium weight), meta desc (medium), and body (low weight)
  Object.entries(INTENT_SIGNALS).forEach(([intent, terms]) => {
    terms.forEach(term => {
      if (title.includes(term)) scores[intent] += 4;
      if (h1.includes(term)) scores[intent] += 3;
      if (desc.includes(term)) scores[intent] += 2;
      // Word boundaries in body
      const regex = new RegExp(`\\b${term.replace(/\s+/g, '\\s+')}\\b`, 'i');
      if (regex.test(body)) scores[intent] += 1;
    });
  });

  // Structural intent signals
  // Has pricing tables or checkout buttons?
  const hasCheckoutCta = /\b(get started|start free trial|sign up now|buy now|add to cart)\b/i.test(body);
  if (hasCheckoutCta) scores.transactional += 3;

  // Has question headings or FAQ?
  if (contentData.qaBlocks?.length >= 2) scores.informational += 3;

  // Has tables comparing features?
  if (contentData.tables?.length >= 1) scores.commercial += 2;

  // Determine Primary and Secondary Intent
  const sortedIntents = Object.entries(scores).sort((a, b) => b[1] - a[1]);
  const primaryIntentKey = sortedIntents[0][1] > 0 ? sortedIntents[0][0] : 'informational';
  const secondaryIntentKey = sortedIntents[1][1] > 0 ? sortedIntents[1][0] : null;

  const INTENT_LABELS = {
    informational: 'Informational (Knowledge Seeking & Guides)',
    navigational: 'Navigational (Brand Destination & Portals)',
    commercial: 'Commercial Investigation (Feature & Vendor Evaluation)',
    transactional: 'Transactional (Direct Action, Trial or Purchase)',
    local: 'Local Intent (Physical Presence & Regional Service)',
  };

  // Evaluate Intent Mismatches
  const mismatches = [];
  let satisfactionScore = 85;

  // Case 1: Transactional intent targeted in Title/H1, but lacking clear action CTAs or pricing
  if (scores.transactional >= 3 && !hasCheckoutCta) {
    mismatches.push({
      type: 'TRANSACTIONAL_CTA_GAP',
      severity: 'HIGH',
      description: 'Page title or heading indicates purchase/sign-up intent, but no prominent primary conversion CTA or pricing trigger was detected.',
      recommendation: 'Add high-contrast primary call-to-action buttons ("Start Free Trial", "Get Started") above the fold and reinforce trust signals.',
    });
    satisfactionScore -= 20;
  }

  // Case 2: Informational guide query with thin content (<400 words)
  if (primaryIntentKey === 'informational' && contentData.wordCount < 400) {
    mismatches.push({
      type: 'THIN_INFORMATIONAL_CONTENT',
      severity: 'HIGH',
      description: `Informational search intent requires comprehensive depth, but page has only ${contentData.wordCount} words.`,
      recommendation: 'Expand topical coverage to answer prerequisite questions, add step-by-step instructions, and include visual or structured data.',
    });
    satisfactionScore -= 25;
  }

  // Case 3: Commercial investigation with no structured comparison
  if (primaryIntentKey === 'commercial' && contentData.tables.length === 0 && contentData.lists.totalLists === 0) {
    mismatches.push({
      type: 'UNSTRUCTURED_COMPARISON',
      severity: 'MEDIUM',
      description: 'Users conducting commercial comparison research need scannable feature matrices, but no comparison tables or specification lists were found.',
      recommendation: 'Format feature trade-offs into an HTML comparison table with clear checkmarks and pricing tiers.',
    });
    satisfactionScore -= 15;
  }

  return {
    primaryIntent: primaryIntentKey,
    primaryIntentLabel: INTENT_LABELS[primaryIntentKey],
    secondaryIntent: secondaryIntentKey,
    secondaryIntentLabel: secondaryIntentKey ? INTENT_LABELS[secondaryIntentKey] : null,
    confidence: Math.min(1.0, parseFloat(((sortedIntents[0][1] + 1) / 10).toFixed(2))),
    intentDistribution: scores,
    satisfactionScore: Math.max(20, satisfactionScore),
    mismatches,
    hasMismatch: mismatches.length > 0,
    intentSummary: `Target classified as ${INTENT_LABELS[primaryIntentKey]} with ${mismatches.length === 0 ? 'strong search intent alignment' : `${mismatches.length} detected intent gaps`}.`,
  };
}

module.exports = {
  classifySearchIntent,
};
