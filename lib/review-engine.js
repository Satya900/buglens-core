import { runDeterministicChecks } from "./rules.js";
import { summarizeRepoProfile } from "./repo-profile.js";

const SEVERITY_ORDER = { HIGH: 3, MEDIUM: 2, LOW: 1 };
const SKIPPED_REVIEW_PATTERNS = [
  /^package-lock\.json$/,
  /^yarn\.lock$/,
  /^pnpm-lock\.yaml$/,
  /\.min\.(js|css)$/,
];

const STRICTNESS_RULES = {
  relaxed: {
    minCommentConfidence: 0.66,
    maxInlineComments: 20,
    requestChangesThreshold: "MEDIUM",
  },
  balanced: {
    minCommentConfidence: 0.7,
    maxInlineComments: 15,
    requestChangesThreshold: "MEDIUM",
  },
  strict: {
    minCommentConfidence: 0.8,
    maxInlineComments: 10,
    requestChangesThreshold: "LOW",
  },
};

function getStrictnessRules(strictness = "balanced") {
  return STRICTNESS_RULES[strictness] || STRICTNESS_RULES.balanced;
}

export function shouldSkipFileReview(filename) {
  return SKIPPED_REVIEW_PATTERNS.some((pattern) => pattern.test(filename));
}

export function getReviewLocation(patch, targetLine = null) {
  const lines = patch.split("\n");
  let currentLineInFile = 0;
  let diffPosition = 0;
  let hasEnteredHunk = false;
  let firstAddedLine = null;

  for (const line of lines) {
    if (line.startsWith("@@")) {
      const match = line.match(/\+(\d+)(?:,\d+)?/);
      if (match) {
        currentLineInFile = Number.parseInt(match[1], 10) - 1;
      }
      hasEnteredHunk = true;
      continue;
    }

    if (!hasEnteredHunk) {
      continue;
    }

    diffPosition += 1;

    const isAddition = line.startsWith("+") && !line.startsWith("+++");
    const isDeletion = line.startsWith("-") && !line.startsWith("---");
    const isContext = !isAddition && !isDeletion;

    if (isAddition || isContext) {
      currentLineInFile += 1;
    }

    if (isAddition && !firstAddedLine) {
      firstAddedLine = { position: diffPosition, line: currentLineInFile };
    }

    if (targetLine && currentLineInFile === targetLine && !isDeletion) {
      return { position: diffPosition, line: currentLineInFile };
    }
  }

  return firstAddedLine || { position: 1, line: 1 };
}

function parseFinding(review, file, defaultLine) {
  const severityMatch = review.match(/\[(HIGH|MEDIUM|LOW)\]/);
  const lineMatch = review.match(/\[Line (\d+)\]/i);
  const suggestionMatch = review.match(/```suggestion\n([\s\S]*?)```/);
  const line = lineMatch ? Number.parseInt(lineMatch[1], 10) : defaultLine;
  const message = review
    .split("```")[0]
    .replace(/⚠️\s*\[(HIGH|MEDIUM|LOW)\]/, "")
    .replace(/\[Line \d+\]/i, "")
    .trim();

  return {
    file,
    line: line || 0,
    severity: severityMatch ? severityMatch[1] : "LOW",
    message: message || "View full AI review on GitHub",
    suggestion: suggestionMatch ? suggestionMatch[1].trim() : null,
    source: "ai",
    category: "general",
  };
}

function normalizeFindingKey(finding) {
  return [finding.file, finding.line || 0, finding.severity, finding.message].join("|");
}

function normalizeOverlapKey(finding) {
  return [
    finding.file,
    finding.line || 0,
    finding.severity,
    finding.category || "general",
  ].join("|");
}

function scoreAiFinding(finding, repoProfile) {
  let confidence = 0.58;

  if (finding.severity === "HIGH") {
    confidence += 0.12;
  }

  if (finding.suggestion) {
    confidence += 0.08;
  }

  if (finding.line > 0) {
    confidence += 0.07;
  }

  if (finding.message.length >= 30) {
    confidence += 0.05;
  }

  if (/security|injection|leak|crash|throw|undefined|null|race|deadlock/i.test(finding.message)) {
    confidence += 0.07;
  }

  if (
    repoProfile &&
    repoProfile.criticalAreas.some((area) => finding.message.toLowerCase().includes(area))
  ) {
    confidence += 0.06;
  }

  return Math.min(Number(confidence.toFixed(2)), 0.92);
}

function addConfidenceAndCategory(findings, repoProfile) {
  return findings.map((finding) => ({
    ...finding,
    confidence: scoreAiFinding(finding, repoProfile),
    category:
      /security|secret|credential|token|password|key|injection|auth/i.test(finding.message)
        ? "security"
        : /package|dependency|library/i.test(finding.message)
          ? "dependency"
          : "correctness",
  }));
}

function formatFindingForComment(finding) {
  const header =
    `⚠️ [${finding.severity}] [Line ${finding.line}] ${finding.message}\n` +
    `Confidence: ${Math.round(finding.confidence * 100)}% | Source: ${finding.source}`;

  if (!finding.suggestion) {
    return header;
  }

  return `${header}\n\n\`\`\`suggestion\n${finding.suggestion}\n\`\`\``;
}

function buildAiPrompt(pr, file, repoProfile) {
  return [
    `PR Title: ${pr.title}`,
    `File: ${file.filename}`,
    summarizeRepoProfile(repoProfile),
    "Review this code diff for high-confidence issues only.",
    "",
    file.patch,
    "",
    "Rules:",
    "1. Maximum 3 findings.",
    "2. Use [HIGH] for security or severe correctness issues, [MEDIUM] for bugs or reliability issues, [LOW] for minor but valid issues.",
    "3. Every finding must begin with [Line XX].",
    "4. Only comment on issues that are directly supported by the diff.",
    "5. If there are no real issues, respond exactly with NO_ISSUES.",
    "6. If you provide a suggestion, it must be valid code and directly fix the issue.",
    "",
    "Output format for each finding:",
    "⚠️ [SEVERITY] [Line XX] [Issue]",
    "",
    "```suggestion",
    "[verified fix]",
    "```",
  ].join("\n");
}

async function reviewFileWithAi(model, pr, file, repoProfile) {
  const aiResponse = await model.generateContent(buildAiPrompt(pr, file, repoProfile));
  const reviewText = aiResponse.response.text().trim();

  if (reviewText === "NO_ISSUES") {
    return { reviewText, findings: [] };
  }

  const findings = reviewText
    .split("⚠️")
    .filter((entry) => entry.trim().length > 10)
    .map((entry) => parseFinding(`⚠️${entry}`, file.filename, null));

  return { reviewText, findings: addConfidenceAndCategory(findings, repoProfile) };
}

function mergeAndRankFindings(findingsMap, patch, findings, inlineComments, strictnessRules) {
  const inlineCommentIndexByOverlap = new Map(
    inlineComments.map((comment, index) => [
      [comment.path, comment.line || 0, comment.severity, comment.category || "general"].join("|"),
      index,
    ])
  );

  for (const finding of findings) {
    const { position, line } = getReviewLocation(patch, finding.line);
    const normalizedFinding = { ...finding, line };
    const findingKey = normalizeFindingKey(normalizedFinding);
    const overlapKey = normalizeOverlapKey(normalizedFinding);

    if (findingsMap.has(findingKey)) {
      const existing = findingsMap.get(findingKey);
      if ((existing.confidence || 0) >= (normalizedFinding.confidence || 0)) {
        continue;
      }
    }

    const overlappingFinding = Array.from(findingsMap.values()).find(
      (existing) => normalizeOverlapKey(existing) === overlapKey
    );
    if (overlappingFinding) {
      const preferExisting =
        (overlappingFinding.source === "rule" && normalizedFinding.source !== "rule") ||
        (overlappingFinding.confidence || 0) >= (normalizedFinding.confidence || 0);

      if (preferExisting) {
        continue;
      }

      findingsMap.delete(normalizeFindingKey(overlappingFinding));
    }

    findingsMap.set(findingKey, normalizedFinding);

    if (inlineComments.length >= strictnessRules.maxInlineComments) {
      continue;
    }

    if ((normalizedFinding.confidence || 0) < strictnessRules.minCommentConfidence) {
      continue;
    }

    const comment = {
      path: normalizedFinding.file,
      line: normalizedFinding.line || 0,
      severity: normalizedFinding.severity,
      category: normalizedFinding.category || "general",
      position,
      body: `🧠 **BugLens Review**\n\n${formatFindingForComment(normalizedFinding)}`,
    };

    if (inlineCommentIndexByOverlap.has(overlapKey)) {
      inlineComments[inlineCommentIndexByOverlap.get(overlapKey)] = comment;
      continue;
    }

    inlineCommentIndexByOverlap.set(overlapKey, inlineComments.length);
    inlineComments.push(comment);
  }
}

export function buildSummary(findings, reviewedFileCount, repoProfile, strictness = "balanced") {
  const strictnessRules = getStrictnessRules(strictness);

  if (findings.length === 0) {
    return {
      decision: "APPROVE",
      riskSummary: "No high-confidence issues detected in changed files.",
      body: [
        "Merge Status: APPROVE",
        "Key Risk: No high-confidence issues detected.",
        "Summary: Reviewed changed files and found no actionable issues worth blocking.",
        "Recommended Action: Merge when CI passes.",
      ].join("\n"),
    };
  }

  const sortedFindings = [...findings].sort((left, right) => {
    const severityDelta = SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity];
    if (severityDelta !== 0) {
      return severityDelta;
    }

    return (right.confidence || 0) - (left.confidence || 0);
  });
  const topFinding = sortedFindings[0];
  const decision =
    SEVERITY_ORDER[topFinding.severity] >= SEVERITY_ORDER[strictnessRules.requestChangesThreshold]
      ? "REQUEST_CHANGES"
      : "APPROVE";
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };

  for (const finding of findings) {
    counts[finding.severity] += 1;
  }

  return {
    decision,
    riskSummary: topFinding.message,
    body: [
      `Merge Status: ${decision}`,
      `Key Risk: ${topFinding.message} (${topFinding.file}:${topFinding.line || 1})`,
      `Summary: ${reviewedFileCount} file(s) reviewed, ${findings.length} high-confidence finding(s) (HIGH: ${counts.HIGH}, MEDIUM: ${counts.MEDIUM}, LOW: ${counts.LOW}). ${summarizeRepoProfile(repoProfile)}`,
      `Recommended Action: Address the ${topFinding.severity.toLowerCase()} severity issue(s) before merging.`,
    ].join("\n"),
  };
}

export async function analyzePullRequest({ files, model, pr, repoProfile, reviewStrictness = "balanced" }) {
  const reviewableFiles = files.filter((file) => file.patch && !shouldSkipFileReview(file.filename));
  const findingsMap = new Map();
  const inlineComments = [];
  const strictnessRules = getStrictnessRules(reviewStrictness);

  for (const file of reviewableFiles) {
    const deterministicFindings = runDeterministicChecks(file);
    mergeAndRankFindings(findingsMap, file.patch, deterministicFindings, inlineComments, strictnessRules);

    if (model) {
      try {
        const aiReview = await reviewFileWithAi(model, pr, file, repoProfile);
        mergeAndRankFindings(findingsMap, file.patch, aiReview.findings, inlineComments, strictnessRules);
      } catch (error) {
        console.error(`AI review failed for ${file.filename}: ${error.message}`);
      }
    }
  }

  const findings = Array.from(findingsMap.values()).sort((left, right) => {
    const severityDelta = SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity];
    if (severityDelta !== 0) {
      return severityDelta;
    }

    return (right.confidence || 0) - (left.confidence || 0);
  });

  return {
    reviewableFiles,
    findings,
    inlineComments,
    summary: buildSummary(findings, reviewableFiles.length, repoProfile, reviewStrictness),
  };
}
