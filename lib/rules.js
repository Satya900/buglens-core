const COMMON_PACKAGE_TYPOS = new Map([
  ["luide-react", "lucide-react"],
  ["react-hook-formm", "react-hook-form"],
  ["tailwindcsss", "tailwindcss"],
  ["nextt", "next"],
]);

function extractAddedLines(patch) {
  const lines = patch.split("\n");
  let currentNewLine = 0;
  const addedLines = [];

  for (const line of lines) {
    if (line.startsWith("@@")) {
      const match = line.match(/\+(\d+)(?:,\d+)?/);
      if (match) {
        currentNewLine = Number.parseInt(match[1], 10) - 1;
      }
      continue;
    }

    const isAddition = line.startsWith("+") && !line.startsWith("+++");
    const isDeletion = line.startsWith("-") && !line.startsWith("---");

    if (isAddition) {
      currentNewLine += 1;
      addedLines.push({ lineNumber: currentNewLine, content: line.slice(1) });
      continue;
    }

    if (!isDeletion) {
      currentNewLine += 1;
    }
  }

  return addedLines;
}

function createRuleFinding(file, line, severity, message, options = {}) {
  return {
    file,
    line,
    severity,
    message,
    suggestion: options.suggestion || null,
    source: "rule",
    category: options.category || "correctness",
    ruleId: options.ruleId || "unknown_rule",
    confidence: options.confidence ?? 0.95,
  };
}

// ─── Levenshtein distance helper ────────────────────────────────────────────
function levenshteinDistance(a, b) {
  const m = a.length;
  const n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) =>
    Array.from({ length: n + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j - 1], dp[i - 1][j], dp[i][j - 1]);
    }
  }
  return dp[m][n];
}

// ─── Rule: hardcoded secrets ─────────────────────────────────────────────────
function detectHardcodedSecrets(file) {
  const findings = [];

  for (const addedLine of extractAddedLines(file.patch)) {
    const content = addedLine.content.trim();
    const looksSensitive =
      /(api[_-]?key|secret|token|password)\s*[:=]\s*["'][^"']{8,}["']/i.test(content) &&
      !/process\.env|import\.meta\.env|secrets?manager|vault/i.test(content);

    if (!looksSensitive) continue;

    findings.push(
      createRuleFinding(
        file.filename,
        addedLine.lineNumber,
        "HIGH",
        "Possible hardcoded secret added in the diff.",
        { category: "security", ruleId: "hardcoded_secret", confidence: 0.98 }
      )
    );
  }

  return findings;
}

// ─── Rule: eval / new Function ───────────────────────────────────────────────
function detectDynamicExecution(file) {
  const findings = [];

  for (const addedLine of extractAddedLines(file.patch)) {
    const content = addedLine.content.trim();
    if (!/\beval\s*\(|\bnew Function\s*\(/.test(content)) continue;

    findings.push(
      createRuleFinding(
        file.filename,
        addedLine.lineNumber,
        "HIGH",
        "Dynamic code execution was introduced. This is a high-risk security pattern.",
        { category: "security", ruleId: "dynamic_execution", confidence: 0.97 }
      )
    );
  }

  return findings;
}

// ─── Rule: shell execution ───────────────────────────────────────────────────
function detectShellExecution(file) {
  const findings = [];

  for (const addedLine of extractAddedLines(file.patch)) {
    const content = addedLine.content.trim();
    if (!/\bchild_process\.(exec|execSync)\s*\(/.test(content)) continue;

    findings.push(
      createRuleFinding(
        file.filename,
        addedLine.lineNumber,
        "MEDIUM",
        "Shell execution was added. Validate inputs carefully to avoid command injection.",
        { category: "security", ruleId: "shell_execution", confidence: 0.9 }
      )
    );
  }

  return findings;
}

// ─── Rule: suspicious package names in package.json ──────────────────────────
function detectSuspiciousDependencies(file) {
  if (file.filename !== "package.json") return [];

  const findings = [];

  for (const addedLine of extractAddedLines(file.patch)) {
    const packageNameMatch = addedLine.content.match(/"([^"]+)"\s*:/);
    if (!packageNameMatch) continue;

    const packageName = packageNameMatch[1];
    const correctedName = COMMON_PACKAGE_TYPOS.get(packageName);
    if (!correctedName) continue;

    findings.push(
      createRuleFinding(
        file.filename,
        addedLine.lineNumber,
        "MEDIUM",
        `Suspicious dependency name "${packageName}". This looks like a typo for "${correctedName}".`,
        {
          category: "dependency",
          ruleId: "dependency_typo",
          confidence: 0.96,
          suggestion: `  "${correctedName}": "REPLACE_WITH_INTENDED_VERSION"`,
        }
      )
    );
  }

  return findings;
}

// ─── Rule: critical TODOs ────────────────────────────────────────────────────
function detectDisabledAssertions(file) {
  const findings = [];

  for (const addedLine of extractAddedLines(file.patch)) {
    const content = addedLine.content.trim();
    if (
      !/\b(todo|fixme)\b/i.test(content) ||
      !/security|auth|validation|sanitize/i.test(content)
    )
      continue;

    findings.push(
      createRuleFinding(
        file.filename,
        addedLine.lineNumber,
        "LOW",
        "A TODO/FIXME references a safety-critical area. This often means an incomplete guard landed in production code.",
        { category: "reliability", ruleId: "critical_todo", confidence: 0.75 }
      )
    );
  }

  return findings;
}

// ─── Rule: variable name mismatch (typo detection) ───────────────────────────
// Catches cases like: const supabaseAnonKey = ... used as supabasenonKey
function detectVariableNameMismatch(file) {
  if (!/\.(js|ts|jsx|tsx|mjs|cjs)$/.test(file.filename)) return [];

  const addedLines = extractAddedLines(file.patch);

  // Collect all variable declarations from added lines
  const declared = new Map(); // name → lineNumber
  for (const { lineNumber, content } of addedLines) {
    const m = content.match(/(?:^|[\s;{(])(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=/);
    if (m) declared.set(m[1], lineNumber);
  }

  if (declared.size === 0) return [];

  const declaredNames = Array.from(declared.keys());
  const findings = [];
  const reported = new Set();

  for (const { lineNumber, content } of addedLines) {
    // Skip declaration lines and comments
    if (/(?:const|let|var)\s+[\w$]+\s*=/.test(content)) continue;
    if (content.trim().startsWith("//") || content.trim().startsWith("*")) continue;

    const identifiers = [...new Set((content.match(/\b[A-Za-z_$][\w$]{3,}\b/g) || []))];

    for (const id of identifiers) {
      if (declared.has(id)) continue; // exact match — fine

      for (const name of declaredNames) {
        if (id === name) continue;

        const dist = levenshteinDistance(id, name);
        const key = `${id}|${name}`;

        // Flag if 1-2 character difference and similar length — very likely a typo
        if (dist <= 2 && Math.abs(id.length - name.length) <= 3 && !reported.has(key)) {
          reported.add(key);
          findings.push(
            createRuleFinding(
              file.filename,
              lineNumber,
              "HIGH",
              `Variable name mismatch: '${id}' is used but '${name}' was declared. This is likely a typo and will cause a ReferenceError.`,
              {
                category: "correctness",
                ruleId: "variable_name_mismatch",
                confidence: 0.92,
                suggestion: id, // simple: suggest replacing with the declared name
              }
            )
          );
        }
      }
    }
  }

  return findings;
}

// ─── Rule: missing await on async-looking calls ──────────────────────────────
// Catches: const user = getCurrentUser(request)  ← no await
function detectMissingAwait(file) {
  if (!/\.(js|ts|jsx|tsx|mjs|cjs)$/.test(file.filename)) return [];

  // Function name prefixes that strongly imply async
  const ASYNC_PREFIXES =
    /^(?:get|fetch|find|load|create|update|delete|save|send|check|validate|resolve|query|retrieve|generate|authenticate|authorize|sign(?:In|Up|Out)|log(?:In|Out))[A-Z]/;

  const findings = [];

  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const trimmed = content.trim();

    // Skip comments, function definitions, and lines already using await
    if (trimmed.startsWith("//") || trimmed.startsWith("*")) continue;
    if (trimmed.includes("await ")) continue;
    if (/\basync\s+(function|\(|\w+\s*=>)/.test(trimmed)) continue;

    // Must be an assignment: const/let/var x = someFunction(
    const assignMatch = trimmed.match(
      /(?:const|let|var)\s+\w[\w$]*\s*=\s*([A-Za-z_$][\w$.]*)\s*\(/
    );
    if (!assignMatch) continue;

    const callee = assignMatch[1].split(".").pop(); // handle obj.method()
    if (!ASYNC_PREFIXES.test(callee)) continue;

    findings.push(
      createRuleFinding(
        file.filename,
        lineNumber,
        "HIGH",
        `Possible missing 'await' before '${callee}(...)'. Without await the variable holds a Promise object, not the resolved value — all downstream code using it will silently break.`,
        {
          category: "correctness",
          ruleId: "missing_await",
          confidence: 0.85,
        }
      )
    );
  }

  return findings;
}

// ─── Rule: import path typos in JS/TS files ──────────────────────────────────
function detectImportPathTypos(file) {
  if (!/\.(js|ts|jsx|tsx|mjs|cjs)$/.test(file.filename)) return [];

  // Well-known packages and their correct names for fuzzy matching
  const KNOWN_PACKAGES = [
    "@supabase/supabase-js",
    "react",
    "react-dom",
    "next",
    "express",
    "axios",
    "mongoose",
    "prisma",
    "@prisma/client",
    "zod",
    "lodash",
    "lucide-react",
    "tailwindcss",
    "typescript",
  ];

  const findings = [];

  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const trimmed = content.trim();
    if (!trimmed.startsWith("import") && !trimmed.includes("require(")) continue;

    const importMatch = trimmed.match(/from\s+['"]([^'"]+)['"]/) ||
                        trimmed.match(/require\s*\(\s*['"]([^'"]+)['"]\s*\)/);
    if (!importMatch) continue;

    const importPath = importMatch[1];

    // Only check bare package names (not relative paths)
    if (importPath.startsWith(".") || importPath.startsWith("/")) continue;

    // Strip leading @ scope for comparison
    for (const known of KNOWN_PACKAGES) {
      if (importPath === known) break; // exact match — fine

      const dist = levenshteinDistance(importPath, known);
      // Flag if very close to a known package but not identical
      if (dist >= 1 && dist <= 3 && Math.abs(importPath.length - known.length) <= 4) {
        findings.push(
          createRuleFinding(
            file.filename,
            lineNumber,
            "HIGH",
            `Possible import path typo: '${importPath}'. Did you mean '${known}'? This will cause a module-not-found error at runtime.`,
            {
              category: "dependency",
              ruleId: "import_path_typo",
              confidence: 0.91,
              suggestion: `from '${known}'`,
            }
          )
        );
        break; // only report once per line
      }
    }
  }

  return findings;
}

const RULES = [
  detectHardcodedSecrets,
  detectDynamicExecution,
  detectShellExecution,
  detectSuspiciousDependencies,
  detectDisabledAssertions,
  detectVariableNameMismatch,
  detectMissingAwait,
  detectImportPathTypos,
];

export function runDeterministicChecks(file) {
  if (!file.patch) return [];
  return RULES.flatMap((rule) => rule(file));
}
