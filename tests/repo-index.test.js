/**
 * Unit tests for the pure functions in lib/repo-index.js.
 * Run with: node --test tests/*.test.js
 */
import { strict as assert } from "assert";
import { describe, it } from "node:test";
import {
  extractFileImports,
  diffAgainstStoredIndex,
  buildContextFromGraph,
} from "../lib/repo-index.js";

describe("extractFileImports", () => {
  it("resolves a relative import against the file's own directory", () => {
    const content = `import { foo } from './helpers';\n`;
    const result = extractFileImports(content, "lib/index.js");
    assert.deepEqual(result, ["lib/helpers"]);
  });

  it("resolves a parent-relative import", () => {
    const content = `import { foo } from '../shared/utils';\n`;
    const result = extractFileImports(content, "lib/feature/index.js");
    assert.deepEqual(result, ["lib/shared/utils"]);
  });

  it("resolves a @/ alias import to src/", () => {
    const content = `import { Button } from '@/components/Button';\n`;
    const result = extractFileImports(content, "app/page.tsx");
    assert.deepEqual(result, ["src/components/Button"]);
  });

  it("ignores node_modules / bare package imports", () => {
    const content = `import express from 'express';\nimport { z } from 'zod';\n`;
    const result = extractFileImports(content, "index.js");
    assert.deepEqual(result, []);
  });

  it("dedupes repeated imports of the same path", () => {
    const content = `import { a } from './x';\nimport { b } from './x';\n`;
    const result = extractFileImports(content, "index.js");
    assert.deepEqual(result, ["x"]);
  });

  it("handles require() as well as import", () => {
    const content = `const foo = require('./foo');\n`;
    const result = extractFileImports(content, "index.js");
    assert.deepEqual(result, ["foo"]);
  });

  it("returns empty array for no content", () => {
    assert.deepEqual(extractFileImports(null, "index.js"), []);
    assert.deepEqual(extractFileImports("", "index.js"), []);
  });
});

describe("diffAgainstStoredIndex", () => {
  it("classifies a brand-new file as changed", () => {
    const tree = [{ path: "a.js", sha: "sha-a" }];
    const stored = [];
    const { changed, unchanged, deleted } = diffAgainstStoredIndex(tree, stored);
    assert.equal(changed.length, 1);
    assert.equal(unchanged.length, 0);
    assert.equal(deleted.length, 0);
  });

  it("classifies a file with matching blob sha as unchanged", () => {
    const tree = [{ path: "a.js", sha: "sha-a" }];
    const stored = [{ file_path: "a.js", blob_sha: "sha-a" }];
    const { changed, unchanged } = diffAgainstStoredIndex(tree, stored);
    assert.equal(changed.length, 0);
    assert.equal(unchanged.length, 1);
  });

  it("classifies a file with a differing blob sha as changed", () => {
    const tree = [{ path: "a.js", sha: "sha-new" }];
    const stored = [{ file_path: "a.js", blob_sha: "sha-old" }];
    const { changed, unchanged } = diffAgainstStoredIndex(tree, stored);
    assert.equal(changed.length, 1);
    assert.equal(unchanged.length, 0);
  });

  it("classifies a stored file no longer in the tree as deleted", () => {
    const tree = [{ path: "a.js", sha: "sha-a" }];
    const stored = [
      { file_path: "a.js", blob_sha: "sha-a" },
      { file_path: "removed.js", blob_sha: "sha-gone" },
    ];
    const { deleted } = diffAgainstStoredIndex(tree, stored);
    assert.deepEqual(deleted, ["removed.js"]);
  });
});

describe("buildContextFromGraph", () => {
  function makeFilesByPath(entries) {
    return new Map(Object.entries(entries));
  }

  it("includes files the changed file imports (hop 1)", () => {
    const filesByPath = makeFilesByPath({
      "a.js": { imports: ["b.js"], imported_by: [], head_snippet: "// a" },
      "b.js": { imports: [], imported_by: ["a.js"], head_snippet: "// b content" },
    });
    const result = buildContextFromGraph(["a.js"], filesByPath);
    assert.match(result, /b\.js/);
    assert.match(result, /b content/);
  });

  it("includes files that import the changed file (hop 1, reverse edge)", () => {
    const filesByPath = makeFilesByPath({
      "a.js": { imports: [], imported_by: ["caller.js"], head_snippet: "// a" },
      "caller.js": { imports: ["a.js"], imported_by: [], head_snippet: "// caller content" },
    });
    const result = buildContextFromGraph(["a.js"], filesByPath);
    assert.match(result, /caller\.js/);
  });

  it("expands to depth 2", () => {
    const filesByPath = makeFilesByPath({
      "a.js": { imports: ["b.js"], imported_by: [], head_snippet: "// a" },
      "b.js": { imports: ["c.js"], imported_by: ["a.js"], head_snippet: "// b" },
      "c.js": { imports: [], imported_by: ["b.js"], head_snippet: "// c content, two hops away" },
    });
    const result = buildContextFromGraph(["a.js"], filesByPath);
    assert.match(result, /c\.js/);
    assert.match(result, /two hops away/);
  });

  it("never includes the changed file itself in the output", () => {
    const filesByPath = makeFilesByPath({
      "a.js": { imports: ["b.js"], imported_by: [], head_snippet: "// a itself" },
      "b.js": { imports: [], imported_by: ["a.js"], head_snippet: "// b" },
    });
    const result = buildContextFromGraph(["a.js"], filesByPath);
    assert.doesNotMatch(result, /a itself/);
  });

  it("returns empty string when there is nothing related", () => {
    const filesByPath = makeFilesByPath({
      "a.js": { imports: [], imported_by: [], head_snippet: "// a" },
    });
    const result = buildContextFromGraph(["a.js"], filesByPath);
    assert.equal(result, "");
  });
});
