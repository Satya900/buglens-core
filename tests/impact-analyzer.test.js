/**
 * Unit tests for impact-analyzer path grounding + JSON extraction.
 * Run with: node --test tests/impact-analyzer.test.js
 */
import { strict as assert } from "assert";
import { describe, it } from "node:test";
import {
  extractJsonArray,
  identifyImpactedFiles,
} from "../lib/impact-analyzer.js";

describe("extractJsonArray", () => {
  it("parses a fenced json array", () => {
    const text = 'Here you go:\n```json\n["src/a.ts", "src/b.ts"]\n```';
    assert.deepEqual(extractJsonArray(text), ["src/a.ts", "src/b.ts"]);
  });

  it("parses a bare array and ignores trailing prose brackets", () => {
    const text = 'Result: ["src/a.ts"]\nSee [docs] for more.';
    assert.deepEqual(extractJsonArray(text), ["src/a.ts"]);
  });

  it("returns [] for NONE", () => {
    assert.deepEqual(extractJsonArray("NONE"), []);
  });

  it("returns null on unparseable text", () => {
    assert.equal(extractJsonArray("no array here"), null);
  });
});

describe("identifyImpactedFiles", () => {
  it("returns dependents from the index graph only", () => {
    const known = new Map([
      ["src/api.ts", { imports: [], imported_by: ["src/page.tsx", "src/missing.ts"] }],
      ["src/page.tsx", { imports: ["src/api.ts"], imported_by: [] }],
    ]);
    const files = [{ filename: "src/api.ts" }];
    assert.deepEqual(identifyImpactedFiles({ files, knownFilesByPath: known }), [
      "src/page.tsx",
    ]);
  });

  it("returns empty when the index is missing (no hallucination)", () => {
    const files = [{ filename: "src/api.ts" }];
    assert.deepEqual(identifyImpactedFiles({ files, knownFilesByPath: null }), []);
    assert.deepEqual(identifyImpactedFiles({ files, knownFilesByPath: new Map() }), []);
  });

  it("skips paths that are also in the PR diff", () => {
    const known = new Map([
      ["src/a.ts", { imports: [], imported_by: ["src/b.ts"] }],
      ["src/b.ts", { imports: ["src/a.ts"], imported_by: [] }],
    ]);
    const files = [{ filename: "src/a.ts" }, { filename: "src/b.ts" }];
    assert.deepEqual(identifyImpactedFiles({ files, knownFilesByPath: known }), []);
  });
});
