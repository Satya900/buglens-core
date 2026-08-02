/**
 * Unit tests for deterministic rule checks in lib/rules.js
 * Run with: node --test tests/rules.test.js
 */
import { strict as assert } from "assert";
import { describe, it } from "node:test";
import { runDeterministicChecks } from "../lib/rules.js";

function makeFile(filename, patch) {
  return { filename, patch };
}

describe("detectHardcodedSecrets", () => {
  it("flags a plaintext API key assignment", () => {
    const file = makeFile("config.js", `@@ -0,0 +1,1 @@\n+const API_KEY = "sk-abcdefghijklmnop";\n`);
    const findings = runDeterministicChecks(file);
    assert.equal(findings.length, 1);
    assert.equal(findings[0].severity, "HIGH");
    assert.equal(findings[0].category, "security");
    assert.equal(findings[0].ruleId, "hardcoded_secret");
  });

  it("does not flag process.env references", () => {
    const file = makeFile("config.js", `@@ -0,0 +1,1 @@\n+const API_KEY = process.env.API_KEY;\n`);
    const findings = runDeterministicChecks(file);
    assert.equal(findings.length, 0);
  });

  it("does not flag short values under 8 chars", () => {
    const file = makeFile("config.js", `@@ -0,0 +1,1 @@\n+const secret = "abc";\n`);
    const findings = runDeterministicChecks(file);
    assert.equal(findings.length, 0);
  });
});

describe("detectDynamicExecution", () => {
  it("flags eval()", () => {
    const file = makeFile("utils.js", `@@ -0,0 +1,1 @@\n+eval(userInput);\n`);
    const findings = runDeterministicChecks(file);
    assert.ok(findings.some((f) => f.ruleId === "dynamic_execution"));
  });

  it("flags new Function()", () => {
    const file = makeFile("utils.js", `@@ -0,0 +1,1 @@\n+const fn = new Function('return 1');\n`);
    const findings = runDeterministicChecks(file);
    assert.ok(findings.some((f) => f.ruleId === "dynamic_execution"));
  });

  it("does not flag regular function declarations", () => {
    const file = makeFile("utils.js", `@@ -0,0 +1,1 @@\n+function add(a, b) { return a + b; }\n`);
    const findings = runDeterministicChecks(file);
    assert.equal(findings.filter((f) => f.ruleId === "dynamic_execution").length, 0);
  });
});

describe("detectShellExecution", () => {
  it("flags child_process.exec", () => {
    const file = makeFile("deploy.js", `@@ -0,0 +1,1 @@\n+exec(userCommand);\n`);
    const findings = runDeterministicChecks(file);
    // exec alone doesn't match — needs child_process.exec
    assert.equal(findings.filter((f) => f.ruleId === "shell_execution").length, 0);
  });

  it("flags child_process.exec with full import", () => {
    const file = makeFile("deploy.js", `@@ -0,0 +1,1 @@\n+child_process.exec(cmd);\n`);
    const findings = runDeterministicChecks(file);
    assert.ok(findings.some((f) => f.ruleId === "shell_execution"));
    assert.equal(findings.find((f) => f.ruleId === "shell_execution").severity, "MEDIUM");
  });
});

describe("detectSuspiciousDependencies", () => {
  it("flags a known package typo", () => {
    const file = makeFile("package.json", `@@ -0,0 +1,1 @@\n+  "luide-react": "^0.383.0"\n`);
    const findings = runDeterministicChecks(file);
    assert.ok(findings.some((f) => f.ruleId === "dependency_typo"));
    assert.ok(findings[0].message.includes("lucide-react"));
  });

  it("ignores correct package names", () => {
    const file = makeFile("package.json", `@@ -0,0 +1,1 @@\n+  "lucide-react": "^0.383.0"\n`);
    const findings = runDeterministicChecks(file);
    assert.equal(findings.filter((f) => f.ruleId === "dependency_typo").length, 0);
  });

  it("ignores package.json check on other files", () => {
    const file = makeFile("src/config.js", `@@ -0,0 +1,1 @@\n+  "luide-react": "^0.383.0"\n`);
    const findings = runDeterministicChecks(file);
    assert.equal(findings.filter((f) => f.ruleId === "dependency_typo").length, 0);
  });
});

describe("detectDisabledAssertions", () => {
  it("flags TODO in a security-sensitive context", () => {
    const file = makeFile("auth.js", `@@ -0,0 +1,1 @@\n+// TODO: add auth validation here\n`);
    const findings = runDeterministicChecks(file);
    assert.ok(findings.some((f) => f.ruleId === "critical_todo"));
  });

  it("does not flag TODO without security context", () => {
    const file = makeFile("utils.js", `@@ -0,0 +1,1 @@\n+// TODO: refactor this loop\n`);
    const findings = runDeterministicChecks(file);
    assert.equal(findings.filter((f) => f.ruleId === "critical_todo").length, 0);
  });
});

describe("detectVariableNameMismatch", () => {
  it("does not flag 'repo' as a typo of 'res' (regression: false positive)", () => {
    const file = makeFile(
      "github.js",
      `@@ -0,0 +1,5 @@\n` +
        `+async function fetchFile(octokit, owner, repo, filePath) {\n` +
        `+  const res = await octokit.repos.getContent({ owner, repo, path: filePath });\n` +
        `+  if (!res) return null;\n` +
        `+  console.log(\`Fetching from \${repo}\`);\n` +
        `+  return res.data;\n` +
        `+}\n`
    );
    const findings = runDeterministicChecks(file);
    assert.equal(findings.filter((f) => f.ruleId === "variable_name_mismatch").length, 0);
  });

  it("does not flag 'prev' as a typo of 'res' (regression: false positive)", () => {
    const file = makeFile(
      "counter.js",
      `@@ -0,0 +1,4 @@\n` +
        `+function useCounter() {\n` +
        `+  const res = fetchInitial();\n` +
        `+  setCount(prev => prev + res);\n` +
        `+  return res;\n` +
        `+}\n`
    );
    const findings = runDeterministicChecks(file);
    assert.equal(findings.filter((f) => f.ruleId === "variable_name_mismatch").length, 0);
  });

  it("still flags a genuine long-identifier typo (supabaseAnonKey vs supabasenonKey)", () => {
    const file = makeFile(
      "supabase.js",
      `@@ -0,0 +1,2 @@\n` +
        `+const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;\n` +
        `+console.log(supabasenonKey);\n`
    );
    const findings = runDeterministicChecks(file);
    const hit = findings.find((f) => f.ruleId === "variable_name_mismatch");
    assert.ok(hit, "expected a variable_name_mismatch finding");
    assert.equal(hit.severity, "HIGH");
    assert.match(hit.message, /supabasenonKey/);
    assert.match(hit.message, /supabaseAnonKey/);
  });
});

describe("runDeterministicChecks", () => {
  it("returns empty array for file with no patch", () => {
    const file = makeFile("image.png", null);
    const findings = runDeterministicChecks(file);
    assert.deepEqual(findings, []);
  });

  it("returns empty array for deleted file with empty patch", () => {
    const file = makeFile("old.js", "");
    const findings = runDeterministicChecks(file);
    assert.deepEqual(findings, []);
  });

  it("every finding has required fields", () => {
    const file = makeFile("config.js", `@@ -0,0 +1,1 @@\n+const API_KEY = "sk-abcdefghijklmnop";\n`);
    const findings = runDeterministicChecks(file);
    for (const f of findings) {
      assert.ok(f.file, "missing file");
      assert.ok(["HIGH", "MEDIUM", "LOW"].includes(f.severity), "invalid severity");
      assert.ok(f.message, "missing message");
      assert.ok(f.source === "rule", "source must be 'rule'");
      assert.ok(typeof f.confidence === "number", "confidence must be a number");
    }
  });
});
