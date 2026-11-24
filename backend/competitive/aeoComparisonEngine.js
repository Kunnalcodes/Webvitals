/**
 * AEO (Answer Engine Optimization) Competitive Engine & Question Gap Analyzer — WebVitals 2.0
 *
 * Compares primary vs competitor across 7-stage user journey question coverage,
 * direct answer quality (inverted pyramid), and FAQ structure completeness.
 */

'use strict';

/**
 * Classifies an AEO question into one of the 7 user journey stages.
 */
function classifyJourneyStage(questionText) {
  const q = (questionText || '').toLowerCase();
  if (/pricing|cost|price|plan|fee|discount|license/i.test(q)) return 'Evaluation';
  if (/how to (sign up|buy|purchase|order|checkout|trial)/i.test(q)) return 'Purchase';
  if (/how to (install|deploy|integrate|setup|configure|start)/i.test(q)) return 'Implementation';
  if (/error|fail|troubleshoot|fix|problem|bug|slow|issue/i.test(q)) return 'Troubleshooting';
  if (/support|contact|help|sla|guarantee|warranty|docs|refund/i.test(q)) return 'Ongoing Support';
  if (/how does|how do|workflow|features|methodology|options/i.test(q)) return 'Research';
  return 'Awareness'; // what is, overview, why, concept
}

/**
 * Evaluates and compares AEO question answering performance between primary and competitor.
 *
 * @param {Object} primaryInventory
 * @param {Object} competitorInventory
 * @param {Array<Object>} discoveredKeywords
 * @returns {Object} AEO comparative analysis and question gaps
 */
function compareAeoReadiness(primaryInventory, competitorInventory, discoveredKeywords = []) {
  const pHome = primaryInventory.homepage || {};
  const cHome = competitorInventory.homepage || {};
  const pQa = pHome.semantic?.qaBlocks || [];
  const cQa = cHome.semantic?.qaBlocks || [];

  // Question candidate queries
  const questionKeywords = discoveredKeywords.filter(
    k => k.category === 'question' || /^(what|how|why|when|where|who|can|should|is|are|does|do|best)\b/i.test(k.keyword)
  );

  // 7 User Journey Stages
  const stages = [
    'Awareness',
    'Research',
    'Evaluation',
    'Purchase',
    'Implementation',
    'Troubleshooting',
    'Ongoing Support'
  ];

  const primaryStageCoverage = {
    Awareness: 0,
    Research: 0,
    Evaluation: 0,
    Purchase: 0,
    Implementation: 0,
    Troubleshooting: 0,
    'Ongoing Support': 0
  };

  const competitorStageCoverage = {
    Awareness: 0,
    Research: 0,
    Evaluation: 0,
    Purchase: 0,
    Implementation: 0,
    Troubleshooting: 0,
    'Ongoing Support': 0
  };

  const detailedQuestionGaps = [];

  questionKeywords.forEach(qKw => {
    const stage = classifyJourneyStage(qKw.keyword);
    let gapType = 'Neither Answered';
    let quality = 'Unoptimized';

    if (qKw.primaryPresent && qKw.competitorPresent) {
      gapType = 'Both Answered';
      quality = 'Competitive Overlap';
      primaryStageCoverage[stage] = (primaryStageCoverage[stage] || 0) + 1;
      competitorStageCoverage[stage] = (competitorStageCoverage[stage] || 0) + 1;
    } else if (qKw.competitorPresent && !qKw.primaryPresent) {
      gapType = 'Competitor Answered / Primary Gap';
      quality = 'Competitor Advantage';
      competitorStageCoverage[stage] = (competitorStageCoverage[stage] || 0) + 1;
    } else if (qKw.primaryPresent && !qKw.competitorPresent) {
      gapType = 'Primary Answered / Competitor Gap';
      quality = 'Primary Advantage';
      primaryStageCoverage[stage] = (primaryStageCoverage[stage] || 0) + 1;
    } else {
      gapType = 'Untapped Question';
      quality = 'Market Opportunity';
    }

    if (detailedQuestionGaps.length < 20) {
      detailedQuestionGaps.push({
        question: qKw.keyword,
        stage,
        gapType,
        answerQuality: quality,
        competitorEvidence: qKw.competitorPresent ? `Answered on ${qKw.competitorTargetPage || competitorInventory.domain}` : 'No explicit on-page answer',
        primaryEvidence: qKw.primaryPresent ? `Answered on ${qKw.primaryTargetPage || primaryInventory.domain}` : 'No direct answer block discovered',
        recommendedFormat: 'Direct 40-word answer block + bulleted key specifications',
        suggestedOutline: [
          'Direct concise answer in bold (under 50 words)',
          'Technical explanation or step-by-step checklist',
          'Related documentation or pricing link'
        ],
        priority: gapType.includes('Competitor Answered') ? 'P0' : 'P1',
      });
    }
  });

  // Calculate AEO Scores (0-100)
  const pAnsweredCount = Object.values(primaryStageCoverage).reduce((a, b) => a + b, 0) + pQa.length;
  const cAnsweredCount = Object.values(competitorStageCoverage).reduce((a, b) => a + b, 0) + cQa.length;

  const primaryAeoScore = Math.min(100, Math.max(30, 45 + (pAnsweredCount * 6) + (pQa.length > 0 ? 15 : 0)));
  const competitorAeoScore = Math.min(100, Math.max(30, 45 + (cAnsweredCount * 6) + (cQa.length > 0 ? 15 : 0)));

  const stageComparison = stages.map(stg => ({
    stage: stg,
    primaryQuestions: primaryStageCoverage[stg] || 0,
    competitorQuestions: competitorStageCoverage[stg] || 0,
    leader: (primaryStageCoverage[stg] || 0) > (competitorStageCoverage[stg] || 0) ? 'Primary' :
            (competitorStageCoverage[stg] || 0) > (primaryStageCoverage[stg] || 0) ? 'Competitor' : 'Parity',
  }));

  return {
    primaryAeoScore,
    competitorAeoScore,
    aeoLeader: primaryAeoScore > competitorAeoScore ? 'Primary' : competitorAeoScore > primaryAeoScore ? 'Competitor' : 'Parity',
    scoreDifference: Math.abs(primaryAeoScore - competitorAeoScore),
    pQaBlocksFound: pQa.length,
    cQaBlocksFound: cQa.length,
    stageComparison,
    questionGaps: detailedQuestionGaps,
  };
}

module.exports = {
  classifyJourneyStage,
  compareAeoReadiness,
};
