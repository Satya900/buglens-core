import { runDeterministicChecks } from "./rules.js";
import { summarizeRepoProfile } from "./repo-profile.js";
import { identifyImpactedFiles, buildImpactSummary } from "./impact-analyzer.js";

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
    minCommentConfidence: 0.6,
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
  let confidence = 0.65; // raised base — AI findings that passed the prompt are already filtered

  if (finding.severity === "HIGH") {
    confidence += 0.1;
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

const SEVERITY_EMOJI = { HIGH: "🔴", MEDIUM: "🟡", LOW: "🔵" };
const SEVERITY_LABEL = { HIGH: "High", MEDIUM: "Medium", LOW: "Low" };

function formatFindingForComment(finding) {
  const emoji = SEVERITY_EMOJI[finding.severity] || "⚠️";
  const label = SEVERITY_LABEL[finding.severity] || finding.severity;
  const confidence = Math.round((finding.confidence || 0) * 100);

  const lines = [
    `### ${emoji} BugLens · ${label} Severity`,
    ``,
    finding.message,
    ``,
    `> **Confidence:** ${confidence}% &nbsp;|&nbsp; **Category:** ${finding.category || "general"} &nbsp;|&nbsp; **Source:** ${finding.source}`,
  ];

  if (finding.suggestion) {
    lines.push(``, `**Suggested fix:**`, ``, "```suggestion", finding.suggestion, "```");
  }

  return lines.join("\n");
}

function buildAiPrompt(pr, file, repoProfile, context = {}) {
  const lessons =
    context.lessons && context.lessons.length > 0
      ? [
          "Lessons from previous reviews in this repo:",
          ...context.lessons.map((l) => `- ${l}`),
          "",
        ].join("\n")
      : "";

  const impact = context.impactSummary || "";

  return [
    `You are a senior code reviewer performing a thorough line-by-line review.`,
    ``,
    `PR Title: ${pr.title}`,
    `File: ${file.filename}`,
    summarizeRepoProfile(repoProfile),
    lessons,
    impact,
    ``,
    `== DIFF ==`,
    file.patch,
    `== END DIFF ==`,
    ``,
    `Review the diff above thoroughly. Check for ALL of the following categories:`,
    ``,
    `**CORRECTNESS (HIGH priority)**`,
    `1. UNDEFINED / MISNAMED VARIABLES — Every variable that is USED must be DECLARED with exact spelling. Look for subtle typos.`,
    `2. MISSING AWAIT — Every async call whose return value is used must be awaited. A missing await means a Promise object is used instead of the resolved value — silent breakage.`,
    `3. SYNTAX ERRORS — Unclosed strings, missing brackets, incomplete function calls.`,
    `4. LOGIC BUGS — Null/undefined access without guard, off-by-one, broken conditionals, unreachable code, wrong operator (= vs ==, & vs &&).`,
    ``,
    `**FRAMEWORK & LANGUAGE PATTERNS (MEDIUM priority)**`,
    `5. REACT HOOKS — useEffect/useCallback/useMemo with missing or incorrect dependency arrays. Hook called conditionally or in a loop.`,
    `6. IMPORT PATH ERRORS — Wrong path, dropped/swapped characters, importing from wrong package.`,
    `7. TYPE SAFETY — TypeScript: \`any\` where a real type exists, unsafe type assertions, non-null assertions on nullable values.`,
    `8. ASYNC/PROMISE ERRORS — Unhandled promise rejection, .then() chaining mixed with await, catch missing on async calls.`,
    ``,
    `**CODE QUALITY (LOW priority)**`,
    `9. DEAD CODE — Unreachable statements, unused variables/imports in the diff, commented-out code left in.`,
    `10. PERFORMANCE — Expensive operations inside render without memoization, object/array literals recreated on every render.`,
    `11. SECURITY — Hardcoded secrets, injection vectors, dangerouslySetInnerHTML with unsanitized input, exposed credentials.`,
    `12. ERROR HANDLING — Missing try/catch around network calls, missing null checks on API responses.`,
    ``,
    `Rules:`,
    `- Report up to 8 findings total. Always report HIGH first.`,
    `- [HIGH] = will cause a crash, ReferenceError, data loss, or security breach.`,
    `- [MEDIUM] = will cause bugs under realistic conditions or violates framework rules.`,
    `- [LOW] = minor concern, bad practice, or tech debt.`,
    `- Every finding MUST include [Line XX] with the exact line number from the diff.`,
    `- Only report issues visible in the diff. Do not speculate about code outside the diff.`,
    `- Be specific: name the variable, function, or line that has the issue.`,
    `- Only respond with NO_ISSUES if the diff is trivially safe (e.g. only comments, whitespace, or config values changed).`,
    ``,
    `Output format for each finding:`,
    `⚠️ [SEVERITY] [Line XX] Description of the issue`,
    ``,
    "```suggestion",
    "[corrected code for that line]",
    "```",
  ].join("\n");
}

async function reviewFileWithAi(model, pr, file, repoProfile, context = {}) {
  const aiResponse = await model.generateContent(buildAiPrompt(pr, file, repoProfile, context));
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

    // HIGH severity findings always post — never filtered by confidence threshold
    const meetsThreshold =
      normalizedFinding.severity === "HIGH" ||
      (normalizedFinding.confidence || 0) >= strictnessRules.minCommentConfidence;

    if (!meetsThreshold) {
      continue;
    }

    const comment = {
      path: normalizedFinding.file,
      line: normalizedFinding.line || 0,
      severity: normalizedFinding.severity,
      category: normalizedFinding.category || "general",
      position,
      body: formatFindingForComment(normalizedFinding),
    };

    if (inlineCommentIndexByOverlap.has(overlapKey)) {
      inlineComments[inlineCommentIndexByOverlap.get(overlapKey)] = comment;
      continue;
    }

    inlineCommentIndexByOverlap.set(overlapKey, inlineComments.length);
    inlineComments.push(comment);
  }
}

const DASHBOARD_URL = process.env.DASHBOARD_URL || "https://buglens.app";

export function buildSummary(findings, reviewableFiles, repoProfile, strictness = "balanced", options = {}) {
  const { impactedFiles = [] } = options;
  const reviewedFileCount = Array.isArray(reviewableFiles) ? reviewableFiles.length : reviewableFiles;
  const strictnessRules = getStrictnessRules(strictness);

  // ── Decision ──────────────────────────────────────────────────────────────
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  const sortedFindings = [...findings].sort((a, b) => {
    const d = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
    return d !== 0 ? d : (b.confidence || 0) - (a.confidence || 0);
  });

  const topFinding = sortedFindings[0] || null;
  const decision = topFinding &&
    SEVERITY_ORDER[topFinding.severity] >= SEVERITY_ORDER[strictnessRules.requestChangesThreshold]
    ? "REQUEST_CHANGES"
    : "APPROVE";

  // ── Header ────────────────────────────────────────────────────────────────
  const decisionBadge = decision === "APPROVE"
    ? "✅ **APPROVED** — No blocking issues. Ready to merge."
    : `⚠️ **REQUEST CHANGES** — ${counts.HIGH > 0 ? counts.HIGH + " critical" : counts.MEDIUM + " medium"} issue(s) must be addressed before merging.`;

  const findingsSummary = findings.length === 0
    ? "None"
    : [
        counts.HIGH > 0 ? `🔴 ${counts.HIGH} HIGH` : null,
        counts.MEDIUM > 0 ? `🟡 ${counts.MEDIUM} MEDIUM` : null,
        counts.LOW > 0 ? `🔵 ${counts.LOW} LOW` : null,
      ].filter(Boolean).join(" · ");

  const lines = [
    `## 🧠 BugLens Review`,
    ``,
    `> ${decisionBadge}`,
    ``,
    `| | |`,
    `|---|---|`,
    `| **Files reviewed** | ${reviewedFileCount} |`,
    `| **Findings** | ${findingsSummary} |`,
    `| **Strictness** | ${strictness} |`,
  ];

  // ── Files table ───────────────────────────────────────────────────────────
  if (Array.isArray(reviewableFiles) && reviewableFiles.length > 0) {
    const filesWithIssues = new Set(findings.map((f) => f.file));

    lines.push(``, `---`, ``, `### 📋 Changes Reviewed`, ``);
    lines.push(`| File | Status |`);
    lines.push(`|---|---|`);

    for (const file of reviewableFiles) {
      const hasIssue = filesWithIssues.has(file.filename);
      lines.push(`| \`${file.filename}\` | ${hasIssue ? "⚠️ Issues found" : "✅ Clean"} |`);
    }
  }

  // ── Findings table ────────────────────────────────────────────────────────
  if (findings.length > 0) {
    lines.push(``, `---`, ``, `### 🔍 Findings`, ``);
    lines.push(`| # | Severity | File | Line | Issue |`);
    lines.push(`|---|---|---|---|---|`);

    sortedFindings.forEach((f, i) => {
      const emoji = SEVERITY_EMOJI[f.severity] || "⚠️";
      const shortMsg = f.message.length > 90 ? f.message.slice(0, 87) + "…" : f.message;
      lines.push(
        `| ${i + 1} | ${emoji} ${f.severity} | \`${f.file}\` | ${f.line || "—"} | ${shortMsg} |`
      );
    });
  }

  // ── Cross-file impact ─────────────────────────────────────────────────────
  if (impactedFiles.length > 0) {
    lines.push(``, `---`, ``, `### ⚡ Potential Cross-file Impact`, ``);
    lines.push(`Changes in this PR may affect files outside the diff:`);
    lines.push(``);
    for (const f of impactedFiles) lines.push(`- \`${f}\``);
  }

  // ── Pre-merge checklist ───────────────────────────────────────────────────
  if (findings.length > 0) {
    lines.push(``, `---`, ``, `### ✅ Pre-merge Checklist`, ``);
    if (counts.HIGH > 0) lines.push(`- [ ] Resolve **${counts.HIGH} HIGH** severity finding(s)`);
    if (counts.MEDIUM > 0) lines.push(`- [ ] Resolve **${counts.MEDIUM} MEDIUM** severity finding(s)`);
    if (impactedFiles.length > 0) {
      lines.push(`- [ ] Verify cross-file impact in: ${impactedFiles.map((f) => `\`${f}\``).join(", ")}`);
    }
  }

  // ── Footer ────────────────────────────────────────────────────────────────
  lines.push(
    ``,
    `---`,
    ``,
    `<sub>Reviewed by [BugLens AI](${DASHBOARD_URL}) · [View dashboard](${DASHBOARD_URL}/reviews) · [Manage settings](${DASHBOARD_URL}/settings)</sub>`
  );

  return {
    decision,
    riskSummary: topFinding ? topFinding.message : "No issues detected.",
    body: lines.join("\n"),
  };
}

export async function analyzePullRequest({
  files,
  model,
  pr,
  repoProfile,
  reviewStrictness = "balanced",
  lessons = [],
}) {
  const reviewableFiles = files.filter((file) => file.patch && !shouldSkipFileReview(file.filename));
  const findingsMap = new Map();
  const inlineComments = [];
  const strictnessRules = getStrictnessRules(reviewStrictness);

  // 1. Cross-File Impact Analysis (Point 2)
  console.log(`Running cross-file impact analysis for ${pr.title}...`);
  const impactedFiles = await identifyImpactedFiles({ model, pr, files });
  const impactSummary = buildImpactSummary(impactedFiles);

  const context = {
    lessons, // Point 3: Feedback Loop
    impactedFiles,
    impactSummary,
  };

  const BATCH_SIZE = 10;
  for (let i = 0; i < reviewableFiles.length; i += BATCH_SIZE) {
    const batch = reviewableFiles.slice(i, i + BATCH_SIZE);
    console.log(`Analyzing batch ${Math.floor(i / BATCH_SIZE) + 1} (${batch.length} files)...`);

    for (const file of batch) {
      const deterministicFindings = runDeterministicChecks(file);
      mergeAndRankFindings(
        findingsMap,
        file.patch,
        deterministicFindings,
        inlineComments,
        strictnessRules
      );

      if (model) {
        try {
          const aiReview = await reviewFileWithAi(model, pr, file, repoProfile, context);
          mergeAndRankFindings(
            findingsMap,
            file.patch,
            aiReview.findings,
            inlineComments,
            strictnessRules
          );
        } catch (error) {
          console.error(`AI review failed for ${file.filename}: ${error.message}`);
        }
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
    impactedFiles,
    summary: buildSummary(findings, reviewableFiles, repoProfile, reviewStrictness, { impactedFiles }),
  };
}
