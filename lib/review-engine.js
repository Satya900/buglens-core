import { runDeterministicChecks } from "./rules.js";
import { summarizeRepoProfile } from "./repo-profile.js";
import { identifyImpactedFiles, buildImpactSummary } from "./impact-analyzer.js";
import { getCodebaseContext } from "./codebase-context.js";
import { isExcludedFile } from "./file-filters.js";

const SEVERITY_ORDER = { HIGH: 3, MEDIUM: 2, LOW: 1 };

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
  return isExcludedFile(filename);
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

// ── Language detection ────────────────────────────────────────────────────────
function detectLanguage(filename) {
  if (/\.(tsx|jsx)$/.test(filename)) return "react";
  if (/\.(ts)$/.test(filename)) return "typescript";
  if (/\.(js|mjs|cjs)$/.test(filename)) return "javascript";
  if (/\.py$/.test(filename)) return "python";
  if (/\.go$/.test(filename)) return "go";
  if (/\.rs$/.test(filename)) return "rust";
  if (/\.(java|kt)$/.test(filename)) return "java";
  if (/\.rb$/.test(filename)) return "ruby";
  if (/\.(css|scss|sass)$/.test(filename)) return "css";
  if (/\.(sql)$/.test(filename)) return "sql";
  return "generic";
}

function getLanguageChecks(lang) {
  const base = [
    "LOGIC BUGS: Off-by-one errors, broken conditions (= vs ==, & vs &&), unreachable code, wrong operator precedence.",
    "NULL / UNDEFINED ACCESS: Property access on a value that could be null or undefined without a guard.",
    "MISSING ERROR HANDLING: Network calls, file I/O, or JSON.parse without try/catch or .catch().",
    "HARDCODED SECRETS: API keys, tokens, passwords, private URLs embedded in code.",
    "DEAD CODE: Unreachable statements, unused variables/imports introduced in this diff.",
    "NAMING TYPOS: Variables used with a spelling different from their declaration (e.g. `userNmae` vs `userName`).",
  ];

  const extra = {
    react: [
      "REACT HOOKS — MISSING DEPS: useEffect/useCallback/useMemo with a dependency array that is missing variables used inside the callback. Name each missing dep.",
      "REACT HOOKS — STALE CLOSURE: A hook that reads a value from outer scope but doesn't list it in deps, causing stale data on re-render.",
      "HOOKS RULES VIOLATION: Hook called inside a condition, loop, or nested function.",
      "UNNECESSARY RE-RENDERS: Object/array/function literal created inline inside JSX or passed as a prop without useMemo/useCallback — recreated every render.",
      "MISSING KEY PROP: .map() rendering JSX without a stable `key` prop.",
      "ASYNC IN USEEFFECT: async function directly passed to useEffect instead of defined inside — returns a Promise that React ignores.",
      "DANGEROUS HTML: dangerouslySetInnerHTML used without sanitizing the input.",
      "MISSING AWAIT: async call whose return value is used but not awaited — variable holds a Promise, not the resolved value.",
      "IMPORT PATH ERRORS: Typos in import paths, wrong package name, incorrect relative path.",
    ],
    typescript: [
      "UNSAFE ANY: `as any` or `: any` used where a real type exists — defeats type safety.",
      "NON-NULL ASSERTION ABUSE: `!` non-null assertion on a value that can realistically be null/undefined.",
      "MISSING AWAIT: async call whose return value is used but not awaited.",
      "TYPE WIDENING: Value typed too broadly (e.g. `string` when it should be a union literal) losing useful type narrowing downstream.",
      "IMPORT PATH ERRORS: Typos in import paths or package names.",
      "UNHANDLED PROMISE: .then()/.catch() chain missing a .catch(), or async function call with no error handling.",
    ],
    javascript: [
      "MISSING AWAIT: async call whose return value is used but not awaited — silent Promise bug.",
      "VAR HOISTING: `var` used instead of `let`/`const` causing unexpected hoisting.",
      "== vs ===: Loose equality used where strict equality is needed.",
      "CALLBACK ERROR IGNORED: Node-style callback where the `err` argument is not checked.",
      "IMPORT PATH ERRORS: Typos in require/import paths.",
      "UNHANDLED PROMISE: async call or .then() chain with no .catch().",
    ],
    python: [
      "BARE EXCEPT: `except:` or `except Exception:` swallowing errors silently.",
      "MUTABLE DEFAULT ARGUMENT: Function default argument is a list or dict — shared across all calls, mutated state bug.",
      "DANGEROUS EVAL: `eval()` or `exec()` on user-controlled data.",
      "SHELL INJECTION: subprocess with `shell=True` and user-controlled input.",
      "UNSAFE DESERIALIZATION: `pickle.loads()` on untrusted data.",
      "MISSING RETURN: Function that should return a value has a code path that falls off without returning.",
      "SHADOWED BUILTIN: Variable named `list`, `dict`, `type`, `id`, `input`, etc., shadowing the builtin.",
      "WILDCARD IMPORT: `from module import *` polluting namespace.",
    ],
    go: [
      "IGNORED ERROR: `_, err :=` or `_ = someFunc()` where the error is discarded.",
      "DEFER IN LOOP: `defer` inside a loop — deferred calls accumulate and run at function exit, not loop iteration end.",
      "GOROUTINE LEAK: Goroutine started with no mechanism to stop it (missing context cancellation, channel close).",
      "NIL POINTER DEREFERENCE: Pointer used without a nil check after a function that can return nil.",
      "RACE CONDITION: Shared variable accessed from multiple goroutines without synchronization.",
      "HARDCODED SECRET: API key, password, or token literal in code.",
    ],
    sql: [
      "SQL INJECTION: String concatenation or interpolation used to build a query instead of parameterized statements.",
      "MISSING WHERE CLAUSE: UPDATE or DELETE without a WHERE clause — affects all rows.",
      "N+1 QUERY: Loop that executes a query per iteration instead of a single batched query.",
      "MISSING INDEX HINT: Query on a large table filtering by a column that likely lacks an index.",
    ],
  };

  return [...base, ...(extra[lang] || [])];
}

// ── Walkthrough prompt ────────────────────────────────────────────────────────
function buildWalkthroughPrompt(pr, files) {
  const fileList = files.map(f => `- ${f.filename} (+${f.additions || 0}/-${f.deletions || 0})`).join("\n");
  return [
    `You are a senior engineer writing a concise PR walkthrough for your team.`,
    ``,
    `PR Title: ${pr.title}`,
    `PR Body: ${pr.body || "(no description)"}`,
    ``,
    `Files changed:`,
    fileList,
    ``,
    `Write a walkthrough with TWO sections:`,
    ``,
    `## Summary`,
    `2-3 sentences. What does this PR do and why? Focus on intent, not mechanics.`,
    ``,
    `## Changes`,
    `A table with columns: File | Change Type | Summary`,
    `Change Type = one of: Feature, Bugfix, Refactor, Config, Test, Docs`,
    ``,
    `Keep it factual. No praise. No filler.`,
  ].join("\n");
}

// ── Main AI review prompt ─────────────────────────────────────────────────────
function buildAiPrompt(pr, file, repoProfile, context = {}) {
  const lang = detectLanguage(file.filename);
  const checks = getLanguageChecks(lang);

  const lessonsBlock =
    context.lessons && context.lessons.length > 0
      ? ["Past issues found in this repo (apply extra scrutiny):", ...context.lessons.map((l) => `  • ${l}`), ""].join("\n")
      : "";

  const impactBlock = context.impactSummary
    ? `Cross-file impact note: ${context.impactSummary}\n`
    : "";

  const codebaseBlock = context.codebaseContext
    ? [
        `## Codebase Context`,
        `The following files are imported by the changed file. Use this to detect breaking changes — if a function signature, type, or export was changed, check whether callers in the diff still match.`,
        `\`\`\``,
        context.codebaseContext,
        `\`\`\``,
        ``,
      ].join("\n")
    : "";

  const checksBlock = checks.map((c, i) => `${i + 1}. ${c}`).join("\n");

  return [
    `You are an expert ${lang} code reviewer with 10+ years of experience. You review diffs with the same rigour as a principal engineer at a top tech company.`,
    ``,
    `## Context`,
    `PR: "${pr.title}"`,
    `File: ${file.filename}  (language: ${lang})`,
    summarizeRepoProfile(repoProfile),
    lessonsBlock,
    impactBlock,
    codebaseBlock,
    `## Diff`,
    `\`\`\`diff`,
    file.patch,
    `\`\`\``,
    ``,
    `## Your Task`,
    ``,
    `**Step 1 — Understand the change (think silently, do NOT output this):**`,
    `Read the diff carefully. Understand what the developer intended to do.`,
    ``,
    `**Step 2 — Hunt for issues using this checklist:**`,
    checksBlock,
    ``,
    `**Step 3 — Output your findings as a JSON array.**`,
    ``,
    `Rules:`,
    `- Report up to 10 findings. Prioritise HIGH severity.`,
    `- HIGH = crash, data loss, security breach, or broken functionality.`,
    `- MEDIUM = bug under realistic conditions, framework rule violation, performance regression.`,
    `- LOW = code smell, bad practice, maintainability concern.`,
    `- line_number: use the NEW file line number (the + side of the diff).`,
    `- Be specific: name the variable, function, or expression that is wrong.`,
    `- suggestion: provide the corrected 1-3 lines of code (not an explanation — actual code).`,
    `- Only flag issues clearly visible in the diff. Do not speculate.`,
    `- If NOTHING is wrong (diff is trivial: whitespace/comments/config only), output: []`,
    ``,
    `Output ONLY valid JSON — no markdown fences, no prose before or after:`,
    `[`,
    `  {`,
    `    "severity": "HIGH" | "MEDIUM" | "LOW",`,
    `    "line_number": <integer>,`,
    `    "category": "correctness" | "security" | "performance" | "style" | "error_handling" | "type_safety" | "react" | "dependency",`,
    `    "title": "<short title, max 10 words>",`,
    `    "description": "<precise explanation of the issue and why it matters>",`,
    `    "suggestion": "<corrected code for this line/block, or null>"`,
    `  }`,
    `]`,
  ].join("\n");
}

// ── Parse JSON findings with fallback ────────────────────────────────────────
function parseAiFindings(rawText, filename) {
  const text = rawText.trim();

  // Try JSON parse first
  try {
    const cleaned = text
      .replace(/^```(?:json)?\s*/i, "")
      .replace(/```\s*$/, "")
      .trim();
    const parsed = JSON.parse(cleaned);
    if (Array.isArray(parsed)) {
      return parsed
        .filter((f) => f && f.severity && f.description)
        .map((f) => ({
          file: filename,
          line: f.line_number || 0,
          severity: ["HIGH", "MEDIUM", "LOW"].includes(f.severity) ? f.severity : "LOW",
          message: f.title ? `**${f.title}** — ${f.description}` : f.description,
          suggestion: f.suggestion && f.suggestion !== "null" ? f.suggestion : null,
          category: f.category || "correctness",
          source: "ai",
        }));
    }
  } catch (_) {
    // fall through to legacy parser
  }

  // Fallback: legacy ⚠️ format
  if (text === "NO_ISSUES" || text === "[]") return [];
  return text
    .split("⚠️")
    .filter((entry) => entry.trim().length > 10)
    .map((entry) => parseFinding(`⚠️${entry}`, filename, null));
}

async function reviewFileWithAi(model, pr, file, repoProfile, context = {}) {
  const aiResponse = await model.generateContent(buildAiPrompt(pr, file, repoProfile, context));
  const reviewText = aiResponse.response.text().trim();

  if (reviewText === "[]" || reviewText === "NO_ISSUES") {
    return { reviewText, findings: [] };
  }

  const raw = parseAiFindings(reviewText, file.filename);
  const findings = addConfidenceAndCategory(raw, repoProfile);
  return { reviewText, findings };
}

// ── PR-level walkthrough ──────────────────────────────────────────────────────
export async function generateWalkthrough(model, pr, files) {
  if (!model) return null;
  try {
    const prompt = buildWalkthroughPrompt(pr, files);
    const res = await model.generateContent(prompt);
    return res.response.text().trim();
  } catch (_) {
    return null;
  }
}

function mergeAndRankFindings(findingsMap, patch, findings, inlineComments, strictnessRules) {
  const inlineCommentIndexByOverlap = new Map(
    inlineComments.map((comment, index) => [
      [comment.path, comment.line || 0, comment.severity, comment.category || "general"].join("|"),
      index,
    ])
  );

  for (const finding of findings) {
    // AI findings already carry the correct new-file line number.
    // Only use getReviewLocation to derive the diff `position` (fallback for
    // edge cases). Never let the resolved line overwrite the AI's reported line —
    // getReviewLocation's fallback is firstAddedLine which can be completely wrong.
    const { position, line: resolvedLine } = getReviewLocation(patch, finding.line);
    const finalLine = finding.line > 0 ? finding.line : resolvedLine;
    const normalizedFinding = { ...finding, line: finalLine, position };
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
  const { impactedFiles = [], walkthrough = null } = options;
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

  // ── Walkthrough ───────────────────────────────────────────────────────────
  if (walkthrough) {
    lines.push(``, `---`, ``, walkthrough);
  }

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
  octokit = null,
  repoFullName = null,
  userId = null,
  sha = null,
  codebaseContextOverride = null,
}) {
  const reviewableFiles = files.filter((file) => file.patch && !shouldSkipFileReview(file.filename));
  const findingsMap = new Map();
  const inlineComments = [];
  const strictnessRules = getStrictnessRules(reviewStrictness);

  // codebaseContextOverride lets callers (the offline eval harness) skip
  // getCodebaseContext entirely, since it touches Supabase/GitHub and this
  // function has no other way to know it's being run without live
  // credentials. null/undefined means "not provided" -> use the real
  // lookup; any string (including "") means "use exactly this."
  const codebaseContextPromise =
    codebaseContextOverride !== null
      ? Promise.resolve(codebaseContextOverride)
      : getCodebaseContext({ octokit, repoFullName, userId, reviewableFiles, sha });

  // 1. Run walkthrough + cross-file impact + codebase context in parallel
  console.log(`Analyzing PR: "${pr.title}" — ${reviewableFiles.length} reviewable files`);
  const [walkthroughText, impactedFiles, codebaseContext] = await Promise.all([
    generateWalkthrough(model, pr, reviewableFiles),
    identifyImpactedFiles({ model, pr, files }),
    codebaseContextPromise,
  ]);
  const impactSummary = buildImpactSummary(impactedFiles);

  if (codebaseContext) {
    const fileCount = (codebaseContext.match(/\/\/ .+ \(first/g) || []).length;
    console.log(`Codebase context: fetched ${fileCount} imported file(s) for PR context`);
  }

  const context = {
    lessons,
    impactedFiles,
    impactSummary,
    codebaseContext,
  };

  // 2. Review files in batches
  const BATCH_SIZE = 10;
  for (let i = 0; i < reviewableFiles.length; i += BATCH_SIZE) {
    const batch = reviewableFiles.slice(i, i + BATCH_SIZE);
    console.log(`Reviewing batch ${Math.floor(i / BATCH_SIZE) + 1}: ${batch.map(f => f.filename).join(", ")}`);

    // Deterministic rules run synchronously, AI runs in parallel across batch
    for (const file of batch) {
      const deterministicFindings = runDeterministicChecks(file);
      mergeAndRankFindings(findingsMap, file.patch, deterministicFindings, inlineComments, strictnessRules);
    }

    if (model) {
      const aiResults = await Promise.allSettled(
        batch.map((file) => reviewFileWithAi(model, pr, file, repoProfile, context))
      );
      for (let j = 0; j < batch.length; j++) {
        const result = aiResults[j];
        if (result.status === "fulfilled") {
          mergeAndRankFindings(findingsMap, batch[j].patch, result.value.findings, inlineComments, strictnessRules);
        } else {
          console.error(`AI review failed for ${batch[j].filename}: ${result.reason?.message}`);
        }
      }
    }
  }

  const findings = Array.from(findingsMap.values()).sort((left, right) => {
    const severityDelta = SEVERITY_ORDER[right.severity] - SEVERITY_ORDER[left.severity];
    if (severityDelta !== 0) return severityDelta;
    return (right.confidence || 0) - (left.confidence || 0);
  });

  return {
    reviewableFiles,
    findings,
    inlineComments,
    impactedFiles,
    walkthrough: walkthroughText,
    summary: buildSummary(findings, reviewableFiles, repoProfile, reviewStrictness, { impactedFiles, walkthrough: walkthroughText }),
  };
}
