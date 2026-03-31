import fs from "fs/promises";
import path from "path";
import process from "process";
import { analyzePullRequest } from "../lib/review-engine.js";
import { buildRepoProfile } from "../lib/repo-profile.js";

const FIXTURES_DIR = path.resolve(process.cwd(), "fixtures", "reviews");
const MODE = process.env.EVAL_MODE || "replay";

function normalizeText(value) {
  return String(value || "")
    .toLowerCase()
    .replace(/\s+/g, " ")
    .trim();
}

function normalizeFindingKey(finding) {
  return [
    finding.file,
    finding.severity,
    finding.line || 0,
    normalizeText(finding.message),
  ].join("|");
}

function buildReplayModel(replayResponses = {}) {
  return {
    async generateContent(prompt) {
      const fileLine = prompt
        .split("\n")
        .find((line) => line.startsWith("File: "))
        ?.replace("File: ", "")
        .trim();

      const text = replayResponses[fileLine] || "NO_ISSUES";
      return {
        response: {
          text() {
            return text;
          },
        },
      };
    },
  };
}

function printFixtureResult(result) {
  const status = result.passed ? "PASS" : "FAIL";
  console.log(`\n[${status}] ${result.name}`);
  console.log(
    `Expected ${result.expectedCount}, got ${result.actualCount}, precision ${result.precision.toFixed(2)}, recall ${result.recall.toFixed(2)}`
  );

  if (result.missing.length > 0) {
    console.log("Missing findings:");
    for (const finding of result.missing) {
      console.log(`- ${finding.file}:${finding.line || 0} [${finding.severity}] ${finding.message}`);
    }
  }

  if (result.unexpected.length > 0) {
    console.log("Unexpected findings:");
    for (const finding of result.unexpected) {
      console.log(
        `- ${finding.file}:${finding.line || 0} [${finding.severity}] ${finding.message} ` +
          `(confidence ${Math.round((finding.confidence || 0) * 100)}%)`
      );
    }
  }
}

async function loadFixtures() {
  const entries = await fs.readdir(FIXTURES_DIR, { withFileTypes: true });
  const files = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".json"))
    .map((entry) => path.join(FIXTURES_DIR, entry.name));

  const fixtures = [];
  for (const file of files) {
    const content = await fs.readFile(file, "utf8");
    fixtures.push(JSON.parse(content));
  }

  return fixtures;
}

async function evaluateFixture(fixture) {
  const model = MODE === "deterministic" ? undefined : buildReplayModel(fixture.replay_ai_responses);
  const repoProfile = buildRepoProfile({
    repoFullName: fixture.repo_full_name || "fixture/repo",
    files: fixture.files,
  });
  const analysis = await analyzePullRequest({
    files: fixture.files,
    model,
    pr: fixture.pull_request,
    repoProfile,
  });

  const actualFindings = analysis.findings.map((finding) => ({
    file: finding.file,
    line: finding.line || 0,
    severity: finding.severity,
    message: finding.message,
    confidence: finding.confidence,
  }));
  const expectedFindings = fixture.expected_findings || [];

  const actualMap = new Map(actualFindings.map((finding) => [normalizeFindingKey(finding), finding]));
  const expectedMap = new Map(expectedFindings.map((finding) => [normalizeFindingKey(finding), finding]));

  const missing = expectedFindings.filter((finding) => !actualMap.has(normalizeFindingKey(finding)));
  const unexpected = actualFindings.filter((finding) => !expectedMap.has(normalizeFindingKey(finding)));

  const matchedCount = expectedFindings.length - missing.length;
  const precision = actualFindings.length === 0 ? (expectedFindings.length === 0 ? 1 : 0) : matchedCount / actualFindings.length;
  const recall = expectedFindings.length === 0 ? 1 : matchedCount / expectedFindings.length;
  const minimumPrecision = fixture.thresholds?.min_precision ?? 0.8;
  const minimumRecall = fixture.thresholds?.min_recall ?? 0.8;
  const passed = precision >= minimumPrecision && recall >= minimumRecall && missing.length === 0;

  return {
    name: fixture.name,
    passed,
    expectedCount: expectedFindings.length,
    actualCount: actualFindings.length,
    precision,
    recall,
    missing,
    unexpected,
  };
}

async function main() {
  const fixtures = await loadFixtures();
  if (fixtures.length === 0) {
    console.error("No evaluation fixtures found.");
    process.exit(1);
  }

  const results = [];
  for (const fixture of fixtures) {
    const result = await evaluateFixture(fixture);
    results.push(result);
    printFixtureResult(result);
  }

  const failures = results.filter((result) => !result.passed);
  const averagePrecision =
    results.reduce((sum, result) => sum + result.precision, 0) / results.length;
  const averageRecall = results.reduce((sum, result) => sum + result.recall, 0) / results.length;

  console.log("\nSummary");
  console.log(`Mode: ${MODE}`);
  console.log(`Fixtures: ${results.length}`);
  console.log(`Average precision: ${averagePrecision.toFixed(2)}`);
  console.log(`Average recall: ${averageRecall.toFixed(2)}`);
  console.log(`Failures: ${failures.length}`);

  if (failures.length > 0) {
    process.exit(1);
  }
}

main().catch((error) => {
  console.error("Evaluation crashed:", error);
  process.exit(1);
});
