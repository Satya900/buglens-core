/**
 * Keep README strictness table honest against review-engine thresholds.
 * Run with: node --test tests/strictness.test.js
 */
import { strict as assert } from "assert";
import { describe, it } from "node:test";
import { readFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";
import { getStrictnessConfig } from "../lib/review-engine.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const readme = readFileSync(join(__dirname, "..", "README.md"), "utf8");

describe("strictness docs vs code", () => {
  it("balanced min confidence is 0.6 in code", () => {
    assert.equal(getStrictnessConfig("balanced").minCommentConfidence, 0.6);
  });

  it("README lists balanced as 60%", () => {
    assert.match(readme, /\|\s*balanced\s*\|\s*60%\s*\|/);
    assert.doesNotMatch(readme, /\|\s*balanced\s*\|\s*70%\s*\|/);
  });

  it("README matches relaxed and strict thresholds", () => {
    assert.equal(getStrictnessConfig("relaxed").minCommentConfidence, 0.66);
    assert.equal(getStrictnessConfig("strict").minCommentConfidence, 0.8);
    assert.match(readme, /\|\s*relaxed\s*\|\s*66%\s*\|/);
    assert.match(readme, /\|\s*strict\s*\|\s*80%\s*\|/);
  });
});
