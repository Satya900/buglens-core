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
    // React ecosystem
    "react", "react-dom", "react-router-dom", "react-router",
    "react-hook-form", "react-query", "@tanstack/react-query",
    "react-redux", "@reduxjs/toolkit", "recoil", "jotai", "zustand",
    "react-hot-toast", "react-toastify", "react-icons",
    "framer-motion", "react-spring", "react-dnd",
    "react-table", "@tanstack/react-table",
    "react-select", "react-datepicker",
    // Next.js
    "next", "next-auth", "@next/font", "@next/image",
    // Testing
    "jest", "vitest", "@testing-library/react", "@testing-library/jest-dom",
    "cypress", "playwright", "@playwright/test", "supertest",
    // Styling
    "tailwindcss", "styled-components", "@emotion/react", "@emotion/styled",
    "sass", "postcss", "autoprefixer", "clsx", "class-variance-authority",
    // UI libraries
    "lucide-react", "@radix-ui/react-dialog", "@radix-ui/react-dropdown-menu",
    "shadcn-ui", "@headlessui/react", "@heroicons/react", "antd", "@mui/material",
    "chakra-ui", "@chakra-ui/react",
    // Backend / API
    "express", "fastify", "hono", "koa",
    "cors", "helmet", "morgan", "compression", "express-rate-limit",
    "body-parser", "cookie-parser", "multer",
    // Database
    "mongoose", "prisma", "@prisma/client", "drizzle-orm",
    "pg", "mysql2", "sqlite3", "better-sqlite3",
    "@supabase/supabase-js", "@supabase/ssr",
    "redis", "ioredis", "@upstash/redis",
    // Auth
    "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "passport-local",
    "passport-github2", "argon2",
    // HTTP / networking
    "axios", "node-fetch", "got", "ky", "undici", "superagent",
    // Validation / schema
    "zod", "yup", "joi", "valibot", "class-validator",
    // Utilities
    "lodash", "lodash-es", "ramda", "date-fns", "dayjs", "moment",
    "uuid", "nanoid", "chalk", "dotenv", "cross-env",
    "fs-extra", "glob", "fast-glob", "chokidar",
    // Build tools
    "vite", "@vitejs/plugin-react", "webpack", "esbuild", "rollup",
    "typescript", "ts-node", "tsx", "@types/node", "@types/react",
    // Linting / formatting
    "eslint", "prettier", "husky", "lint-staged",
    // Payments
    "stripe", "@stripe/stripe-js",
    // Email
    "nodemailer", "resend", "@sendgrid/mail",
    // AI / ML
    "@google/generative-ai", "openai", "@anthropic-ai/sdk", "langchain",
    // Cloud / infra
    "@aws-sdk/client-s3", "@aws-sdk/client-ses", "aws-sdk",
    "@google-cloud/storage", "firebase", "firebase-admin",
    // Misc popular
    "socket.io", "socket.io-client", "ws",
    "sharp", "jimp", "pdf-lib",
    "cheerio", "puppeteer", "playwright",
    "bull", "bullmq", "agenda",
    "@octokit/rest", "@octokit/auth-app", "octokit",
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

// ─── Python: eval / exec usage ───────────────────────────────────────────────
function detectPythonEval(file) {
  if (!/\.py$/.test(file.filename)) return [];
  const findings = [];
  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const t = content.trim();
    if (t.startsWith("#")) continue;
    if (/\beval\s*\(|\bexec\s*\(/.test(t)) {
      findings.push(
        createRuleFinding(
          file.filename, lineNumber, "HIGH",
          "Python eval()/exec() executes arbitrary code — a critical security risk if any input originates from user data or external sources.",
          { category: "security", ruleId: "python_eval", confidence: 0.97 }
        )
      );
    }
  }
  return findings;
}

// ─── Python: subprocess shell=True / os.system ───────────────────────────────
function detectPythonShellExec(file) {
  if (!/\.py$/.test(file.filename)) return [];
  const findings = [];
  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const t = content.trim();
    if (t.startsWith("#")) continue;
    const isShellTrue = /subprocess\.\w+\s*\(.*shell\s*=\s*True/.test(t);
    const isOsSystem = /\bos\.system\s*\(/.test(t);
    if (!isShellTrue && !isOsSystem) continue;
    findings.push(
      createRuleFinding(
        file.filename, lineNumber, "HIGH",
        isOsSystem
          ? "os.system() is vulnerable to shell injection. Use subprocess.run() with a list of arguments instead."
          : "subprocess with shell=True is vulnerable to shell injection if any argument includes user input. Pass a list of args and set shell=False.",
        { category: "security", ruleId: "python_shell_exec", confidence: 0.95 }
      )
    );
  }
  return findings;
}

// ─── Python: pickle.loads deserialization risk ───────────────────────────────
function detectPythonPickle(file) {
  if (!/\.py$/.test(file.filename)) return [];
  const findings = [];
  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const t = content.trim();
    if (t.startsWith("#")) continue;
    if (!/\bpickle\.loads?\s*\(/.test(t)) continue;
    findings.push(
      createRuleFinding(
        file.filename, lineNumber, "HIGH",
        "pickle.load/loads() can execute arbitrary code when deserializing untrusted data. Never unpickle data from an untrusted source.",
        { category: "security", ruleId: "python_pickle", confidence: 0.96 }
      )
    );
  }
  return findings;
}

// ─── Python: bare except ─────────────────────────────────────────────────────
function detectPythonBareExcept(file) {
  if (!/\.py$/.test(file.filename)) return [];
  const findings = [];
  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const t = content.trim();
    if (!/^except\s*:/.test(t)) continue;
    findings.push(
      createRuleFinding(
        file.filename, lineNumber, "MEDIUM",
        "Bare 'except:' catches everything including KeyboardInterrupt and SystemExit. Specify the exception type (e.g., 'except Exception:').",
        { category: "reliability", ruleId: "python_bare_except", confidence: 0.98 }
      )
    );
  }
  return findings;
}

// ─── Python: mutable default argument ────────────────────────────────────────
function detectPythonMutableDefault(file) {
  if (!/\.py$/.test(file.filename)) return [];
  const findings = [];
  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const t = content.trim();
    if (!/^\s*def\s+/.test(t)) continue;
    if (!/=\s*(\[\s*\]|\{\s*\})/.test(t)) continue;
    findings.push(
      createRuleFinding(
        file.filename, lineNumber, "MEDIUM",
        "Mutable default argument ([] or {}) is shared across all calls. This is a classic Python gotcha — use None as default and create inside the function body.",
        { category: "correctness", ruleId: "python_mutable_default", confidence: 0.97 }
      )
    );
  }
  return findings;
}

// ─── Python: wildcard imports ─────────────────────────────────────────────────
function detectPythonWildcardImport(file) {
  if (!/\.py$/.test(file.filename)) return [];
  const findings = [];
  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const t = content.trim();
    if (!/^from\s+\S+\s+import\s+\*/.test(t)) continue;
    findings.push(
      createRuleFinding(
        file.filename, lineNumber, "LOW",
        "Wildcard import 'from x import *' pollutes the namespace and makes it hard to trace where names come from. Import only what you need.",
        { category: "style", ruleId: "python_wildcard_import", confidence: 0.99 }
      )
    );
  }
  return findings;
}

// ─── Python: import typos ─────────────────────────────────────────────────────
function detectPythonImportTypos(file) {
  if (!/\.py$/.test(file.filename)) return [];

  const KNOWN_PY_PACKAGES = [
    "requests", "numpy", "pandas", "flask", "django", "fastapi",
    "sqlalchemy", "pydantic", "pytest", "httpx", "aiohttp",
    "celery", "redis", "pymongo", "boto3", "botocore",
    "pillow", "opencv", "scipy", "matplotlib", "seaborn",
    "scikit-learn", "sklearn", "tensorflow", "torch", "transformers",
    "openai", "anthropic", "langchain",
    "click", "typer", "rich", "loguru",
    "alembic", "uvicorn", "gunicorn", "starlette",
    "jinja2", "werkzeug", "itsdangerous",
    "cryptography", "paramiko", "fabric",
    "beautifulsoup4", "lxml", "selenium",
    "arrow", "pendulum", "dateutil",
    "pyyaml", "toml", "python-dotenv", "dotenv",
    "psycopg2", "asyncpg", "aiomysql",
    "stripe", "twilio", "sendgrid",
  ];

  const findings = [];

  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const t = content.trim();
    if (!t.startsWith("import ") && !t.startsWith("from ")) continue;

    const match = t.match(/^(?:import|from)\s+([\w.]+)/) ;
    if (!match) continue;

    const pkg = match[1].split(".")[0]; // top-level package only

    for (const known of KNOWN_PY_PACKAGES) {
      const knownBase = known.split("-")[0]; // e.g., beautifulsoup4 → beautifulsoup4
      if (pkg === known || pkg === knownBase) break;

      const dist = levenshteinDistance(pkg, knownBase);
      if (dist >= 1 && dist <= 2 && Math.abs(pkg.length - knownBase.length) <= 3) {
        findings.push(
          createRuleFinding(
            file.filename, lineNumber, "HIGH",
            `Possible Python import typo: '${pkg}'. Did you mean '${known}'? Typosquatted packages can execute malicious code on install.`,
            { category: "dependency", ruleId: "python_import_typo", confidence: 0.9 }
          )
        );
        break;
      }
    }
  }

  return findings;
}

// ─── Go: ignored errors (result, _ := ) ──────────────────────────────────────
function detectGoIgnoredErrors(file) {
  if (!/\.go$/.test(file.filename)) return [];
  const findings = [];
  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const t = content.trim();
    if (t.startsWith("//")) continue;
    // Matches: something, _ := or something, _ =
    if (!/,\s*_\s*:?=/.test(t)) continue;
    // Likely to be error discard when pattern is: x, _ := someFunc()
    if (!/\w+\s*\(/.test(t)) continue;
    findings.push(
      createRuleFinding(
        file.filename, lineNumber, "MEDIUM",
        "Error return value is being discarded with '_'. Ignoring errors is a common source of silent failures in Go — handle or at least log the error.",
        { category: "reliability", ruleId: "go_ignored_error", confidence: 0.85 }
      )
    );
  }
  return findings;
}

// ─── Go: defer inside for loop ───────────────────────────────────────────────
function detectGoDeferInLoop(file) {
  if (!/\.go$/.test(file.filename)) return [];
  const findings = [];
  let insideForLoop = 0;
  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const t = content.trim();
    if (/^\bfor\b/.test(t)) insideForLoop++;
    if (t === "}" && insideForLoop > 0) insideForLoop--;
    if (insideForLoop > 0 && /^\bdefer\b/.test(t)) {
      findings.push(
        createRuleFinding(
          file.filename, lineNumber, "MEDIUM",
          "defer inside a for loop won't execute until the surrounding function returns — not at the end of each iteration. This can cause resource leaks (e.g., unclosed files). Wrap the loop body in a helper function.",
          { category: "reliability", ruleId: "go_defer_in_loop", confidence: 0.88 }
        )
      );
    }
  }
  return findings;
}

// ─── Go: fmt.Println / fmt.Printf left in production code ────────────────────
function detectGoDebugPrints(file) {
  if (!/\.go$/.test(file.filename)) return [];
  const findings = [];
  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const t = content.trim();
    if (t.startsWith("//")) continue;
    if (!/\bfmt\.Print(f|ln)?\s*\(/.test(t)) continue;
    // Skip main.go and *_test.go — printing is expected there
    if (/main\.go$|_test\.go$/.test(file.filename)) continue;
    findings.push(
      createRuleFinding(
        file.filename, lineNumber, "LOW",
        "fmt.Print left in non-main/test file — this is likely debug output. Use a structured logger (log, zap, slog) instead.",
        { category: "style", ruleId: "go_debug_print", confidence: 0.8 }
      )
    );
  }
  return findings;
}

// ─── Go: hardcoded secrets (language-specific supplement) ────────────────────
function detectGoHardcodedSecrets(file) {
  if (!/\.go$/.test(file.filename)) return [];
  const findings = [];
  for (const { lineNumber, content } of extractAddedLines(file.patch)) {
    const t = content.trim();
    if (t.startsWith("//")) continue;
    const looksSensitive =
      /(apiKey|apiSecret|secretKey|password|token|accessKey)\s*[:=]\s*"[^"]{8,}"/i.test(t) &&
      !/os\.Getenv|viper\.|config\./i.test(t);
    if (!looksSensitive) continue;
    findings.push(
      createRuleFinding(
        file.filename, lineNumber, "HIGH",
        "Possible hardcoded secret in Go source. Use os.Getenv() or a config library to load secrets from environment variables.",
        { category: "security", ruleId: "go_hardcoded_secret", confidence: 0.97 }
      )
    );
  }
  return findings;
}

const RULES = [
  // Universal
  detectHardcodedSecrets,
  detectDisabledAssertions,
  // JS / TS
  detectDynamicExecution,
  detectShellExecution,
  detectSuspiciousDependencies,
  detectVariableNameMismatch,
  detectMissingAwait,
  detectImportPathTypos,
  // Python
  detectPythonEval,
  detectPythonShellExec,
  detectPythonPickle,
  detectPythonBareExcept,
  detectPythonMutableDefault,
  detectPythonWildcardImport,
  detectPythonImportTypos,
  // Go
  detectGoIgnoredErrors,
  detectGoDeferInLoop,
  detectGoDebugPrints,
  detectGoHardcodedSecrets,
];

export function runDeterministicChecks(file) {
  if (!file.patch) return [];
  return RULES.flatMap((rule) => rule(file));
}
