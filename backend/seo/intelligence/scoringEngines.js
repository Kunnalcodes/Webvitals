/**
 * Deterministic Scoring Engines (SEO, GEO, AEO) — WebVitals 2.0
 *
 * Implements transparent, evidence-weighted scoring models for:
 *   1. Search Engine Optimization (SEO)
 *   2. Generative Engine Optimization (GEO)
 *   3. Answer Engine Optimization (AEO)
 */

'use strict';

function gradeForScore(score) {
  if (score >= 90) return { grade: 'A+', label: 'Industry Leading' };
  if (score >= 80) return { grade: 'A', label: 'Strong Posture' };
  if (score >= 70) return { grade: 'B', label: 'Good with Minor Gaps' };
  if (score >= 60) return { grade: 'C', label: 'Needs Improvement' };
  if (score >= 50) return { grade: 'D', label: 'Underperforming' };
  return { grade: 'F', label: 'Critical Optimization Deficit' };
}

/**
 * 1. SEO Scoring Engine (8 Weighted Categories, 100 pts max)
 */
function calculateSeoScore({ parsedData, contentData, crawlData, lighthouse }) {
  const factors = [];
  let totalScore = 0;

  // 1. Technical Accessibility & HTTPS (20 pts)
  const isHttps = crawlData?.url?.startsWith('https:') || false;
  const hasRobots = crawlData?.robotsTxt?.exists || false;
  let techEarned = 0;
  if (isHttps) techEarned += 10;
  if (hasRobots) techEarned += 10;
  totalScore += techEarned;
  factors.push({
    factor: 'Technical Accessibility & Directives',
    weight: 20,
    earned: techEarned,
    status: techEarned >= 20 ? 'Optimal' : techEarned >= 10 ? 'Moderate' : 'Critical Deficit',
    evidence: `${isHttps ? 'HTTPS enforced.' : 'Insecure HTTP.'} ${hasRobots ? 'Robots.txt present.' : 'Missing robots.txt.'}`,
    impact: techEarned < 20 ? -10 : 0,
  });

  // 2. Indexability & Canonicalization (20 pts)
  const hasCanonical = Boolean(parsedData.canonicalUrl);
  const isNoIndex = (parsedData.metaRobots || '').toLowerCase().includes('noindex');
  let indexEarned = 0;
  if (!isNoIndex) indexEarned += 12;
  if (hasCanonical) indexEarned += 8;
  totalScore += indexEarned;
  factors.push({
    factor: 'Indexability & Canonical Directives',
    weight: 20,
    earned: indexEarned,
    status: indexEarned >= 20 ? 'Optimal' : 'Needs Attention',
    evidence: `${isNoIndex ? 'Warning: noindex tag blocks indexing.' : 'Indexable.'} ${hasCanonical ? `Canonical: "${parsedData.canonicalUrl.slice(0, 40)}..."` : 'No canonical tag.'}`,
    impact: isNoIndex ? -12 : !hasCanonical ? -8 : 0,
  });

  // 3. On-Page Metadata & Headings (20 pts)
  const hasTitle = Boolean(parsedData.title && parsedData.title.length >= 20 && parsedData.title.length <= 70);
  const hasDesc = Boolean(parsedData.metaDescription && parsedData.metaDescription.length >= 70 && parsedData.metaDescription.length <= 170);
  const hasSingleH1 = contentData.headingStats.h1 === 1;
  let onPageEarned = 0;
  if (hasTitle) onPageEarned += 8;
  else if (parsedData.title) onPageEarned += 4;
  if (hasDesc) onPageEarned += 6;
  else if (parsedData.metaDescription) onPageEarned += 3;
  if (hasSingleH1) onPageEarned += 6;
  else if (contentData.headingStats.h1 > 1) onPageEarned += 2;
  totalScore += onPageEarned;
  factors.push({
    factor: 'On-Page Metadata & Headings Hierarchy',
    weight: 20,
    earned: onPageEarned,
    status: onPageEarned >= 18 ? 'Optimal' : onPageEarned >= 12 ? 'Moderate' : 'Weak',
    evidence: `Title: ${parsedData.title ? `${parsedData.title.length} chars` : 'Missing'}. Description: ${parsedData.metaDescription ? `${parsedData.metaDescription.length} chars` : 'Missing'}. H1 count: ${contentData.headingStats.h1}.`,
    impact: onPageEarned < 20 ? -(20 - onPageEarned) : 0,
  });

  // 4. Content Quality & Completeness (15 pts)
  const words = contentData.wordCount || 0;
  let contentEarned = 0;
  if (words >= 900) contentEarned = 15;
  else if (words >= 500) contentEarned = 12;
  else if (words >= 300) contentEarned = 8;
  else contentEarned = 4;
  totalScore += contentEarned;
  factors.push({
    factor: 'Content Depth & Topical Completeness',
    weight: 15,
    earned: contentEarned,
    status: contentEarned >= 12 ? 'Optimal' : 'Thin Content',
    evidence: `${words} total words extracted. Reading time: ~${contentData.readingTimeMinutes} min. Boilerplate ratio: ${(contentData.boilerplateRatio * 100).toFixed(0)}%.`,
    impact: contentEarned < 15 ? -(15 - contentEarned) : 0,
  });

  // 5. Internal Linking Architecture (10 pts)
  const internalLinks = contentData.linksAnalysis.internal || 0;
  let linksEarned = 0;
  if (internalLinks >= 12) linksEarned = 10;
  else if (internalLinks >= 5) linksEarned = 7;
  else linksEarned = 3;
  totalScore += linksEarned;
  factors.push({
    factor: 'Internal Linking Architecture',
    weight: 10,
    earned: linksEarned,
    status: linksEarned >= 7 ? 'Optimal' : 'Low Link Density',
    evidence: `${internalLinks} internal links crawled on page. Generic anchor texts: ${contentData.linksAnalysis.genericAnchorsCount}.`,
    impact: linksEarned < 10 ? -(10 - linksEarned) : 0,
  });

  // 6. Structured Data & Schema.org (5 pts)
  const jsonLdCount = parsedData.jsonLd?.length || 0;
  const schemaEarned = jsonLdCount > 0 ? 5 : 1;
  totalScore += schemaEarned;
  factors.push({
    factor: 'Structured Data & Rich Snippets',
    weight: 5,
    earned: schemaEarned,
    status: jsonLdCount > 0 ? 'Optimal' : 'Missing Schema',
    evidence: `${jsonLdCount} JSON-LD structured data blocks discovered.`,
    impact: schemaEarned < 5 ? -4 : 0,
  });

  // 7. Mobile & Viewport (5 pts)
  const hasViewport = Boolean(parsedData.viewport && parsedData.viewport.includes('width=device-width'));
  const mobileEarned = hasViewport ? 5 : 0;
  totalScore += mobileEarned;
  factors.push({
    factor: 'Mobile Viewport Usability',
    weight: 5,
    earned: mobileEarned,
    status: hasViewport ? 'Optimal' : 'Non-Responsive',
    evidence: hasViewport ? 'Valid viewport meta tag detected.' : 'Missing responsive viewport tag.',
    impact: mobileEarned < 5 ? -5 : 0,
  });

  // 8. Performance & Core Web Vitals (5 pts)
  const perfScore = lighthouse?.scores?.performance || 85;
  const perfEarned = Math.round((perfScore / 100) * 5);
  totalScore += perfEarned;
  factors.push({
    factor: 'Page Performance & Web Vitals',
    weight: 5,
    earned: perfEarned,
    status: perfScore >= 80 ? 'Optimal' : 'Needs Optimization',
    evidence: `Lighthouse Performance Score: ${perfScore}/100.`,
    impact: perfEarned < 5 ? -(5 - perfEarned) : 0,
  });

  totalScore = Math.min(100, Math.max(0, totalScore));
  const gradeInfo = gradeForScore(totalScore);

  return {
    score: totalScore,
    grade: gradeInfo.grade,
    gradeLabel: gradeInfo.label,
    factors,
    confidence: 0.95,
  };
}

/**
 * 2. GEO Scoring Engine (Generative Engine Optimization, 100 pts max)
 */
function calculateGeoScore({ parsedData, contentData, entityData, crawlData }) {
  const factors = [];
  let totalScore = 0;

  // 1. Machine Readability & Semantic HTML (20 pts)
  const hasLogicalHeadings = !contentData.headingStats.hasHierarchyIssue;
  const boilerplateRatio = contentData.boilerplateRatio || 0.2;
  let readabilityEarned = 10;
  if (hasLogicalHeadings) readabilityEarned += 6;
  if (boilerplateRatio <= 0.3) readabilityEarned += 4;
  totalScore += readabilityEarned;
  factors.push({
    factor: 'Machine Readability & Semantic HTML',
    weight: 20,
    earned: readabilityEarned,
    status: readabilityEarned >= 16 ? 'High Extraction Quality' : 'Moderate',
    evidence: `Heading hierarchy: ${hasLogicalHeadings ? 'Strictly nested' : 'Hierarchy warnings detected'}. Boilerplate ratio: ${(boilerplateRatio * 100).toFixed(0)}%.`,
    impact: readabilityEarned < 20 ? -(20 - readabilityEarned) : 0,
  });

  // 2. Entity Clarity & Brand Understanding (20 pts)
  const entityClarityScore = entityData.clarityScore || 50;
  const entityEarned = Math.round((entityClarityScore / 100) * 20);
  totalScore += entityEarned;
  factors.push({
    factor: 'Entity Clarity & Brand Knowledge Consistency',
    weight: 20,
    earned: entityEarned,
    status: entityData.clarityRating,
    evidence: `Entity identified: "${entityData.brandName}". Clarity rating: ${entityData.clarityRating} (${entityData.verifiedSignals.length} verified signals, ${entityData.ambiguitySignals.length} ambiguity points).`,
    impact: entityEarned < 20 ? -(20 - entityEarned) : 0,
  });

  // 3. Content Citation Readiness & Empirical Claims (25 pts)
  const bodyText = contentData.cleanBodyText || '';
  const hasStats = /\b\d+(?:\.\d+)?%\b|\b\$\d+(?:,\d{3})*\b/.test(bodyText);
  const hasResearchTerms = /\b(benchmark|study|analysis|survey|methodology|data)\b/i.test(bodyText);
  const hasAuthorBio = Boolean(entityData.authorship?.hasBio || entityData.authorship?.authorName);
  let citationEarned = 8;
  if (hasStats) citationEarned += 7;
  if (hasResearchTerms) citationEarned += 5;
  if (hasAuthorBio) citationEarned += 5;
  totalScore += citationEarned;
  factors.push({
    factor: 'Content Citation Readiness & Data-Backed Claims',
    weight: 25,
    earned: citationEarned,
    status: citationEarned >= 18 ? 'High Quotability' : 'Vague / Low Evidence',
    evidence: `${hasStats ? 'Empirical numerical metrics discovered.' : 'No statistical figures.'} ${hasAuthorBio ? `Author attribution verified: "${entityData.authorship.authorName || 'Identified'}".` : 'Anonymous or uncredited content.'}`,
    impact: citationEarned < 25 ? -(25 - citationEarned) : 0,
  });

  // 4. AI Crawler Access & Technical Discoverability (15 pts)
  const robotsContent = crawlData?.robotsTxt?.contentSample || '';
  const blocksAiBot = /User-agent:\s*(GPTBot|ClaudeBot|PerplexityBot|CCBot)[\s\S]*?Disallow:\s*\//i.test(robotsContent);
  const aiCrawlerEarned = blocksAiBot ? 4 : 15;
  totalScore += aiCrawlerEarned;
  factors.push({
    factor: 'AI Crawler Access & Discovery Policies',
    weight: 15,
    earned: aiCrawlerEarned,
    status: blocksAiBot ? 'Restricted by robots.txt' : 'Open Public Access',
    evidence: blocksAiBot ? 'Explicit disallow directives targeting AI crawlers (GPTBot/ClaudeBot).' : 'Public crawler access open with zero blocking directives.',
    impact: blocksAiBot ? -11 : 0,
  });

  // 5. Factual Structure (Tables, Definitions & Lists) (10 pts)
  const tables = contentData.tables.length;
  const lists = contentData.lists.totalLists;
  const defs = contentData.definitions.length;
  let structEarned = 2;
  if (tables >= 1) structEarned += 4;
  if (lists >= 2) structEarned += 2;
  if (defs >= 1) structEarned += 2;
  structEarned = Math.min(10, structEarned);
  totalScore += structEarned;
  factors.push({
    factor: 'Factual Structure & Scannable Data',
    weight: 10,
    earned: structEarned,
    status: structEarned >= 7 ? 'Structured' : 'Unstructured Prose',
    evidence: `${tables} tables, ${lists} lists, and ${defs} definition blocks extracted.`,
    impact: structEarned < 10 ? -(10 - structEarned) : 0,
  });

  // 6. Topical Authority Signals (10 pts)
  const wordCount = contentData.wordCount || 0;
  const freshnessRecent = contentData.freshness?.isRecent || false;
  let authorityEarned = 3;
  if (wordCount >= 700) authorityEarned += 4;
  if (freshnessRecent) authorityEarned += 3;
  totalScore += authorityEarned;
  factors.push({
    factor: 'Topical Authority & Freshness Signals',
    weight: 10,
    earned: authorityEarned,
    status: authorityEarned >= 7 ? 'Strong Authority' : 'Moderate',
    evidence: `Word count: ${wordCount}. Freshness: ${freshnessRecent ? 'Updated within recent cycle' : 'No explicit recent publication date'}.`,
    impact: authorityEarned < 10 ? -(10 - authorityEarned) : 0,
  });

  totalScore = Math.min(100, Math.max(0, totalScore));
  const gradeInfo = gradeForScore(totalScore);

  const readinessRating = totalScore >= 80 ? 'Optimal for Generative Engines' :
                          totalScore >= 65 ? 'High Generative Readiness' :
                          totalScore >= 50 ? 'Moderate Generative Visibility' : 'Low AI Citations Potential';

  return {
    score: totalScore,
    grade: gradeInfo.grade,
    gradeLabel: gradeInfo.label,
    readinessRating,
    factors,
    confidence: 0.9,
  };
}

/**
 * 3. AEO Scoring Engine (Answer Engine Optimization, 100 pts max)
 */
function calculateAeoScore({ contentData, questionData, intentData }) {
  const factors = [];
  let totalScore = 0;

  // 1. Question Coverage & Search Intent Alignment (25 pts)
  const qCount = questionData.answeredQuestionsCount || 0;
  let qCoverageEarned = 5;
  if (qCount >= 4) qCoverageEarned = 25;
  else if (qCount >= 2) qCoverageEarned = 18;
  else if (qCount >= 1) qCoverageEarned = 12;
  totalScore += qCoverageEarned;
  factors.push({
    factor: 'Question Coverage & High-Intent Queries',
    weight: 25,
    earned: qCoverageEarned,
    status: qCoverageEarned >= 18 ? 'High Coverage' : 'Low Question Density',
    evidence: `${qCount} answered questions discovered on page.`,
    impact: qCoverageEarned < 25 ? -(25 - qCoverageEarned) : 0,
  });

  // 2. Direct Answer Quality & Conciseness (25 pts)
  const directCount = (questionData.answeredQuestions || []).filter(q => q.hasDirectAnswer).length;
  let directEarned = 6;
  if (directCount >= 3) directEarned = 25;
  else if (directCount >= 1) directEarned = 17;
  totalScore += directEarned;
  factors.push({
    factor: 'Direct Answer Quality & Inverted Pyramid',
    weight: 25,
    earned: directEarned,
    status: directCount >= 2 ? 'Direct & Definitive' : 'Fragmented Answers',
    evidence: `${directCount} definitive answer blocks with direct introductory sentences detected.`,
    impact: directEarned < 25 ? -(25 - directEarned) : 0,
  });

  // 3. Answer Formatting (Tables, Lists, Definitions) (20 pts)
  const hasTables = contentData.tables.length > 0;
  const hasLists = contentData.lists.totalLists > 0;
  const hasFaq = questionData.answerStructuresDetected?.hasFaqSchema;
  let formatEarned = 4;
  if (hasTables) formatEarned += 6;
  if (hasLists) formatEarned += 5;
  if (hasFaq) formatEarned += 5;
  totalScore += formatEarned;
  factors.push({
    factor: 'Answer Formatting & Scannability',
    weight: 20,
    earned: formatEarned,
    status: formatEarned >= 15 ? 'Richly Formatted' : 'Moderate',
    evidence: `Tables: ${hasTables ? 'Yes' : 'No'}, Lists: ${hasLists ? 'Yes' : 'No'}, FAQ Schema: ${hasFaq ? 'Yes' : 'No'}.`,
    impact: formatEarned < 20 ? -(20 - formatEarned) : 0,
  });

  // 4. Question Intent Journey Completeness (15 pts)
  const coveredStages = questionData.coveredStagesCount || 0;
  const stageEarned = Math.round((coveredStages / 6) * 15);
  totalScore += stageEarned;
  factors.push({
    factor: 'User Journey Intent Stage Completeness',
    weight: 15,
    earned: stageEarned,
    status: coveredStages >= 4 ? 'Complete Journey' : 'Journey Gaps',
    evidence: `${coveredStages} of 6 buyer/user journey stages answered (Awareness, Research, Evaluation, Decision, Action, Support).`,
    impact: stageEarned < 15 ? -(15 - stageEarned) : 0,
  });

  // 5. Conversational & Featured Snippet Compatibility (15 pts)
  const intentMatch = !intentData.hasMismatch;
  let snippetEarned = 6;
  if (intentMatch) snippetEarned += 5;
  if (directCount >= 1) snippetEarned += 4;
  totalScore += snippetEarned;
  factors.push({
    factor: 'Conversational Search & Snippet Compatibility',
    weight: 15,
    earned: snippetEarned,
    status: snippetEarned >= 12 ? 'Snippet Optimized' : 'Needs Optimization',
    evidence: `${intentMatch ? 'Search intent aligned.' : 'Intent mismatches detected.'} Snippet readiness: ${directCount > 0 ? 'High' : 'Low'}.`,
    impact: snippetEarned < 15 ? -(15 - snippetEarned) : 0,
  });

  totalScore = Math.min(100, Math.max(0, totalScore));
  const gradeInfo = gradeForScore(totalScore);

  return {
    score: totalScore,
    grade: gradeInfo.grade,
    gradeLabel: gradeInfo.label,
    readinessRating: questionData.readinessRating,
    factors,
    confidence: 0.9,
  };
}

module.exports = {
  calculateSeoScore,
  calculateGeoScore,
  calculateAeoScore,
  gradeForScore,
};
