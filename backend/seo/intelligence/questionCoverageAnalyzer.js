/**
 * Question Coverage & User Journey Intent Analyzer — WebVitals 2.0 AEO Intelligence
 *
 * Discovers answered and missing user questions, maps queries across the 6-stage user journey,
 * and assesses direct answer completeness and conversational search suitability.
 */

'use strict';

/**
 * Analyzes question coverage, answer quality, and user journey completeness.
 *
 * @param {Object} contentData
 * @param {Object} entityData
 * @param {Object} intentData
 * @returns {Object} Question coverage and answer engine analysis
 */
function analyzeQuestionCoverage(contentData = {}, entityData = {}, intentData = {}) {
  const qaBlocks = contentData.qaBlocks || [];
  const cleanText = contentData.cleanBodyText || '';
  const brandName = entityData.brandName || 'the product';
  const category = entityData.primaryCategory || 'the topic';

  // 1. Existing Questions Answered on the Page
  const answeredQuestions = qaBlocks.map(q => {
    const hasSubstantialAnswer = q.answerSnippet ? q.answerSnippet.length >= 60 : false;
    const completeness = hasSubstantialAnswer ? 'Complete' : 'Brief / Fragmented';
    return {
      question: q.question,
      source: q.source,
      completeness,
      hasDirectAnswer: hasSubstantialAnswer,
      snippet: q.answerSnippet || 'Answered within surrounding section copy.',
    };
  });

  // 2. Candidate Question Generation based on Category & Brand Entity
  const standardQuestionsByCategory = {
    'SaaS & Cloud Software': [
      { question: `What is ${brandName} and who is it designed for?`, stage: 'Awareness' },
      { question: `How does ${brandName} integrate with existing workflows?`, stage: 'Research' },
      { question: `How does ${brandName} compare to alternative software platforms?`, stage: 'Evaluation' },
      { question: `What are the pricing tiers and plans for ${brandName}?`, stage: 'Decision' },
      { question: `How do I sign up or initiate a free trial of ${brandName}?`, stage: 'Purchase' },
      { question: `How do I access customer support and API documentation?`, stage: 'Support' },
    ],
    'Cybersecurity & Network Defense': [
      { question: `What security vectors and risks does ${brandName} monitor?`, stage: 'Awareness' },
      { question: `How does the ${brandName} scanning and threat detection engine work?`, stage: 'Research' },
      { question: `What compliance frameworks (SOC2, ISO 27001, HIPAA) are supported?`, stage: 'Evaluation' },
      { question: `What is the deployment timeline and cost of ${brandName}?`, stage: 'Decision' },
      { question: `How do I request a penetration test or live security audit?`, stage: 'Purchase' },
      { question: `Where can I find remediation playbooks and security documentation?`, stage: 'Support' },
    ],
    'E-Commerce & Retail': [
      { question: `What products and collections are available at ${brandName}?`, stage: 'Awareness' },
      { question: `What materials, specifications, and sizing standards are used?`, stage: 'Research' },
      { question: `How do customer reviews rate ${brandName}?`, stage: 'Evaluation' },
      { question: `What payment methods and discounts are accepted?`, stage: 'Decision' },
      { question: `What is the checkout and shipping process?`, stage: 'Purchase' },
      { question: `What is the return, refund, and warranty policy?`, stage: 'Support' },
    ],
  };

  const candidatePool = standardQuestionsByCategory[category] || [
    { question: `What core service or problem does ${brandName} address?`, stage: 'Awareness' },
    { question: `How does ${brandName} work and what methodologies are applied?`, stage: 'Research' },
    { question: `Why should customers choose ${brandName} over alternatives?`, stage: 'Evaluation' },
    { question: `What is the cost, pricing structure, or commercial engagement model?`, stage: 'Decision' },
    { question: `How do users get started or contact sales?`, stage: 'Purchase' },
    { question: `What ongoing support, documentation, or guarantees are provided?`, stage: 'Support' },
  ];

  // Evaluate candidate coverage against clean text
  const lowerBody = cleanText.toLowerCase();
  const missingQuestions = [];
  const partiallyAnsweredQuestions = [];

  const journeyCoverage = {
    Awareness: { covered: false, questions: [] },
    Research: { covered: false, questions: [] },
    Evaluation: { covered: false, questions: [] },
    Decision: { covered: false, questions: [] },
    Purchase: { covered: false, questions: [] },
    Support: { covered: false, questions: [] },
  };

  candidatePool.forEach(cq => {
    // Check if key question terms exist in body
    const keywords = cq.question.toLowerCase().replace(/[^a-z0-9\s]/g, '').split(/\s+/).filter(w => w.length > 4);
    const matches = keywords.filter(k => lowerBody.includes(k));
    const coverageRatio = keywords.length > 0 ? matches.length / keywords.length : 0;

    const entry = { question: cq.question, stage: cq.stage, coverageRatio };

    if (coverageRatio >= 0.5) {
      journeyCoverage[cq.stage].covered = true;
      journeyCoverage[cq.stage].questions.push({ question: cq.question, status: 'Answered' });
    } else if (coverageRatio >= 0.25) {
      partiallyAnsweredQuestions.push(entry);
      journeyCoverage[cq.stage].questions.push({ question: cq.question, status: 'Partially Answered' });
    } else {
      missingQuestions.push(entry);
      journeyCoverage[cq.stage].questions.push({ question: cq.question, status: 'Missing' });
    }
  });

  // Map explicitly answered on-page questions to journey stages
  answeredQuestions.forEach(aq => {
    const qLower = (aq.question || '').toLowerCase();
    let matchedStage = 'Research';
    if (/pricing|cost|plan|subscription|tier|buy|fee/i.test(qLower)) matchedStage = 'Decision';
    else if (/what is|overview|concept|problem|who/i.test(qLower)) matchedStage = 'Awareness';
    else if (/vs|compare|alternative|why choose|difference/i.test(qLower)) matchedStage = 'Evaluation';
    else if (/how to (sign up|get started|install|download|purchase|order)|checkout/i.test(qLower)) matchedStage = 'Purchase';
    else if (/support|help|contact|docs|faq|troubleshoot|warranty/i.test(qLower)) matchedStage = 'Support';

    if (journeyCoverage[matchedStage]) {
      journeyCoverage[matchedStage].covered = true;
      journeyCoverage[matchedStage].questions.push({ question: aq.question, status: 'Answered' });
    }
  });

  // Calculate AEO Direct Answer Quality metrics
  const hasDefinitions = contentData.definitions.length > 0;
  const hasTables = contentData.tables.length > 0;
  const hasLists = contentData.lists.totalLists > 0;
  const hasFaqSchema = (answeredQuestions.some(q => q.source === 'schema_faq'));

  // Question Coverage Score (0-100)
  let coverageScore = 30;
  if (answeredQuestions.length >= 3) coverageScore += 25;
  else if (answeredQuestions.length >= 1) coverageScore += 15;

  if (hasFaqSchema) coverageScore += 15;
  if (hasTables || hasDefinitions) coverageScore += 15;
  if (hasLists) coverageScore += 15;

  const coveredStagesCount = Object.values(journeyCoverage).filter(s => s.covered).length;
  coverageScore += (coveredStagesCount * 5);
  coverageScore = Math.min(100, Math.max(20, coverageScore));

  const readinessRating = coverageScore >= 80 ? 'Featured-Snippet Ready' :
                          coverageScore >= 65 ? 'High Answer Quality' :
                          coverageScore >= 50 ? 'Moderate Question Coverage' :
                          coverageScore >= 35 ? 'Needs Answer Structuring' : 'Unoptimized for Answers';

  return {
    score: coverageScore,
    readinessRating,
    answeredQuestionsCount: answeredQuestions.length,
    answeredQuestions: answeredQuestions.slice(0, 10),
    partiallyAnsweredQuestions,
    missingQuestions,
    journeyCoverage,
    coveredStagesCount,
    answerStructuresDetected: {
      hasFaqSchema,
      hasQABlocks: qaBlocks.length > 0,
      hasDefinitions,
      hasTables,
      hasLists,
    },
    aeoSummary: `Evaluated ${answeredQuestions.length} on-page question answer blocks. ${readinessRating} across ${coveredStagesCount} of 6 user journey stages.`,
  };
}

module.exports = {
  analyzeQuestionCoverage,
};
