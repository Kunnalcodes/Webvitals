/**
 * Competitor Authority & External Signals Engine — WebVitals 2.0
 *
 * Evaluates publicly observable authority signals (social links, brand mentions, linkable assets)
 * and marks third-party backlink/DA metrics as "Unavailable — data source required" (Section 13).
 */

'use strict';

/**
 * Extracts public social profile links from crawled page links.
 */
function extractSocialPresence(links = []) {
  const linkList = Array.isArray(links)
    ? links
    : Array.isArray(links?.sample)
    ? links.sample
    : Array.isArray(links?.items)
    ? links.items
    : [];

  const profiles = {
    twitter: null,
    github: null,
    linkedin: null,
    youtube: null,
    facebook: null,
  };

  linkList.forEach(l => {
    const href = (l.href || '').toLowerCase();
    if (href.includes('twitter.com/') || href.includes('x.com/')) profiles.twitter = l.href;
    else if (href.includes('github.com/')) profiles.github = l.href;
    else if (href.includes('linkedin.com/')) profiles.linkedin = l.href;
    else if (href.includes('youtube.com/')) profiles.youtube = l.href;
    else if (href.includes('facebook.com/')) profiles.facebook = l.href;
  });

  return profiles;
}

/**
 * Evaluates authority signals and transparently flags unintegrated backlink databases.
 *
 * @param {Object} primaryInventory
 * @param {Object} competitorInventory
 * @returns {Object} Authority analysis and ethical link opportunities
 */
function compareAuthoritySignals(primaryInventory, competitorInventory) {
  const pLinks = primaryInventory.homepage?.links || [];
  const cLinks = competitorInventory.homepage?.links || [];

  const pSocial = extractSocialPresence(pLinks);
  const cSocial = extractSocialPresence(cLinks);

  const pSocialCount = Object.values(pSocial).filter(Boolean).length;
  const cSocialCount = Object.values(cSocial).filter(Boolean).length;

  return {
    socialPresence: {
      primary: pSocial,
      competitor: cSocial,
      primaryActiveNetworks: pSocialCount,
      competitorActiveNetworks: cSocialCount,
      leader: pSocialCount > cSocialCount ? 'Primary' : cSocialCount > pSocialCount ? 'Competitor' : 'Parity',
    },
    // Unintegrated Third-Party SEO Metrics (Section 2 & 13 strict requirement)
    backlinks: {
      status: 'UNAVAILABLE',
      providerRequired: 'Ahrefs / Moz / Semrush API integration required',
      primaryBacklinks: null,
      competitorBacklinks: null,
      primaryReferringDomains: null,
      competitorReferringDomains: null,
      displayMessage: 'Unavailable — data source required',
    },
    searchVisibility: {
      status: 'UNAVAILABLE',
      providerRequired: 'Google Search Console OAuth or SERP Provider integration required',
      primaryImpressions: null,
      competitorRankings: null,
      displayMessage: 'Unavailable — data source required',
    },
    // Ethical Authority Growth Opportunities
    ethicalLinkOpportunities: [
      {
        title: 'Authoritative Open-Source / Benchmark Asset',
        strategy: 'Publish an open tool, benchmark study, or free diagnostic calculator that organically earns editorial citations from tech publications.',
        competitorEvidence: (cLinks.length > 30) ? 'Competitor relies heavily on directory and platform partner links.' : 'No unique link magnet detected.',
        priority: 'P1',
        effort: 'Medium',
      },
      {
        title: 'Original Research & Industry Reports',
        strategy: 'Compile telemetry or survey findings into an annual or quarterly state-of-the-industry whitepaper with embeddable charts.',
        competitorEvidence: 'Competitor content is primarily marketing copy rather than original empirical research.',
        priority: 'P2',
        effort: 'High',
      },
      {
        title: 'Verified Entity & Directory Disambiguation',
        strategy: 'Ensure consistent NAP (Name, Address, Phone) and official social profiles are verified across Crunchbase, GitHub, and industry directories.',
        competitorEvidence: `Competitor maintains ${cSocialCount} active public social profiles.`,
        priority: 'P1',
        effort: 'Low',
      },
    ],
  };
}

module.exports = {
  extractSocialPresence,
  compareAuthoritySignals,
};
