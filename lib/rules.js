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

function detectHardcodedSecrets(file) {
  const findings = [];

  for (const addedLine of extractAddedLines(file.patch)) {
    const content = addedLine.content.trim();
    const looksSensitive =
      /(api[_-]?key|secret|token|password)\s*[:=]\s*["'][^"']{8,}["']/i.test(content) &&
      !/process\.env|import\.meta\.env|secrets?manager|vault/i.test(content);

    if (!looksSensitive) {
      continue;
    }

    findings.push(
      createRuleFinding(file.filename, addedLine.lineNumber, "HIGH", "Possible hardcoded secret added in the diff.", {
        category: "security",
        ruleId: "hardcoded_secret",
        confidence: 0.98,
      })
    );
  }

  return findings;
}

function detectDynamicExecution(file) {
  const findings = [];

  for (const addedLine of extractAddedLines(file.patch)) {
    const content = addedLine.content.trim();
    if (!/\beval\s*\(|\bnew Function\s*\(/.test(content)) {
      continue;
    }

    findings.push(
      createRuleFinding(
        file.filename,
        addedLine.lineNumber,
        "HIGH",
        "Dynamic code execution was introduced. This is a high-risk security pattern.",
        {
          category: "security",
          ruleId: "dynamic_execution",
          confidence: 0.97,
        }
      )
    );
  }

  return findings;
}

function detectShellExecution(file) {
  const findings = [];

  for (const addedLine of extractAddedLines(file.patch)) {
    const content = addedLine.content.trim();
    if (!/\bchild_process\.(exec|execSync)\s*\(/.test(content)) {
      continue;
    }

    findings.push(
      createRuleFinding(
        file.filename,
        addedLine.lineNumber,
        "MEDIUM",
        "Shell execution was added. Validate inputs carefully to avoid command injection.",
        {
          category: "security",
          ruleId: "shell_execution",
          confidence: 0.9,
        }
      )
    );
  }

  return findings;
}

function detectSuspiciousDependencies(file) {
  if (file.filename !== "package.json") {
    return [];
  }

  const findings = [];

  for (const addedLine of extractAddedLines(file.patch)) {
    const packageNameMatch = addedLine.content.match(/"([^"]+)"\s*:/);
    if (!packageNameMatch) {
      continue;
    }

    const packageName = packageNameMatch[1];
    const correctedName = COMMON_PACKAGE_TYPOS.get(packageName);
    if (!correctedName) {
      continue;
    }

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

function detectDisabledAssertions(file) {
  const findings = [];

  for (const addedLine of extractAddedLines(file.patch)) {
    const content = addedLine.content.trim();
    if (!/\b(todo|fixme)\b/i.test(content) || !/security|auth|validation|sanitize/i.test(content)) {
      continue;
    }

    findings.push(
      createRuleFinding(
        file.filename,
        addedLine.lineNumber,
        "LOW",
        "A TODO/FIXME references a safety-critical area. This often means an incomplete guard landed in production code.",
        {
          category: "reliability",
          ruleId: "critical_todo",
          confidence: 0.75,
        }
      )
    );
  }

  return findings;
}

const RULES = [
  detectHardcodedSecrets,
  detectDynamicExecution,
  detectShellExecution,
  detectSuspiciousDependencies,
  detectDisabledAssertions,
];

export function runDeterministicChecks(file) {
  if (!file.patch) {
    return [];
  }

  return RULES.flatMap((rule) => rule(file));
}
