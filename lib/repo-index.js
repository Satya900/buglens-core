/**
 * repo-index.js
 *
 * Builds and maintains a persisted, structural (file-level, not
 * embedding-based) import graph for a repo's default branch, refreshed on
 * push and on initial repo connect (see index.js's handlePushEvent and the
 * /internal/index-repo endpoint). Used to give AI reviews real cross-file
 * context — files that import, or are imported by, a changed file — instead
 * of codebase-context.js's live per-PR one-hop lookup, which only sees
 * files a changed file directly imports and forgets everything after one
 * review.
 *
 * Design notes:
 * - Incremental: only re-fetches blob content for files whose git blob sha
 *   changed since the last index (the blob sha itself is the content hash,
 *   no separate hashing needed).
 * - Import resolution is a pure in-memory lookup against the full tree's
 *   known paths (unlike codebase-context.js's live lookup, which must probe
 *   GitHub per candidate since it never has the whole tree) — no extra API
 *   calls beyond the tree fetch + blob fetches for changed files.
 * - Zero-failure for individual files: a failed blob fetch skips that one
 *   file, never aborts the whole index.
 */

import path from "path";
import { isExcludedFile } from "./file-filters.js";
import {
  getStoredIndexFiles,
  upsertRepoIndexFiles,
  pruneRepoIndexFiles,
  getRepoIndexMeta,
} from "./supabase.js";

const MAX_INDEXED_FILES = 300;
const MAX_LINES_PER_FILE = 50;
const HEAD_SNIPPET_CHAR_CAP = 2000; // per-file cap so one huge file can't dominate storage
const CONCURRENCY = 8;
const CONTEXT_MAX_TOTAL_CHARS = 6000; // matches codebase-context.js's existing per-review budget
const CODE_FILE_PATTERN = /\.(js|jsx|ts|tsx|mjs|cjs)$/;

// ─── Import extraction — whole-file variant of codebase-context.js's live diff-based extractLocalImports ───

export function extractFileImports(content, filename) {
  if (!content) return [];

  const dir = path.posix.dirname(filename.replace(/\\/g, "/"));
  const importPattern = /(?:from|require)\s*\(\s*['"](\.[^'"]+|@\/[^'"]+)['"]\s*\)|from\s+['"](\.[^'"]+|@\/[^'"]+)['"]/g;

  const seen = new Set();
  const result = [];
  let match;

  while ((match = importPattern.exec(content)) !== null) {
    const raw = match[1] || match[2];
    if (!raw) continue;

    let resolved;
    if (raw.startsWith("@/")) {
      resolved = raw.replace("@/", "src/");
    } else {
      resolved = path.posix.normalize(`${dir}/${raw}`);
    }
    resolved = resolved.replace(/^\.\//, "");

    if (!seen.has(resolved)) {
      seen.add(resolved);
      result.push(resolved);
    }
  }

  return result;
}

function candidatePaths(importPath) {
  if (/\.[a-zA-Z]+$/.test(importPath)) return [importPath];
  return [
    `${importPath}.ts`,
    `${importPath}.tsx`,
    `${importPath}.js`,
    `${importPath}.jsx`,
    `${importPath}/index.ts`,
    `${importPath}/index.tsx`,
    `${importPath}/index.js`,
  ];
}

function resolveImportInTree(importPath, knownPaths) {
  for (const candidate of candidatePaths(importPath)) {
    if (knownPaths.has(candidate)) return candidate;
  }
  return null;
}

// ─── Tree diffing — pure function, unit-tested independently ───

/**
 * Compares a fresh git tree listing against previously stored index rows.
 * `changed` = new or blob-sha-differs (needs a content refetch), `unchanged`
 * = blob sha matches (skip refetch), `deleted` = stored paths no longer
 * present in the tree at all (needs pruning).
 */
export function diffAgainstStoredIndex(treeEntries, storedFiles) {
  const storedByPath = new Map(storedFiles.map((f) => [f.file_path, f.blob_sha]));
  const treePaths = new Set(treeEntries.map((e) => e.path));

  const changed = [];
  const unchanged = [];
  for (const entry of treeEntries) {
    if (storedByPath.get(entry.path) === entry.sha) {
      unchanged.push(entry);
    } else {
      changed.push(entry);
    }
  }

  const deleted = storedFiles.filter((f) => !treePaths.has(f.file_path)).map((f) => f.file_path);

  return { changed, unchanged, deleted };
}

// ─── Full / incremental repo index build ───

async function fetchBlobContent(octokit, owner, repo, fileSha) {
  try {
    const { data } = await octokit.git.getBlob({ owner, repo, file_sha: fileSha });
    if (data.encoding !== "base64" || !data.content) return null;
    return Buffer.from(data.content, "base64").toString("utf8");
  } catch {
    return null;
  }
}

async function fetchInBatches(items, batchSize, worker) {
  const results = [];
  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    results.push(...(await Promise.allSettled(batch.map(worker))));
  }
  return results;
}

/**
 * Builds (or incrementally updates) the full repo index at `sha`: fetches
 * the repo tree, resolves eligible code files, fetches content only for
 * files whose blob sha changed since the last index, builds forward
 * (imports) and reverse (imported_by) edges across the whole file set, and
 * upserts everything. Never throws for an individual file failure.
 */
export async function buildFullRepoIndex({ octokit, repoFullName, userId, sha }) {
  const [owner, repo] = repoFullName.split("/");

  const { data: tree } = await octokit.git.getTree({ owner, repo, tree_sha: sha, recursive: "true" });

  let entries = (tree.tree || [])
    .filter((e) => e.type === "blob")
    .filter((e) => CODE_FILE_PATTERN.test(e.path) && !isExcludedFile(e.path));

  const capped = entries.length > MAX_INDEXED_FILES || tree.truncated === true;
  if (entries.length > MAX_INDEXED_FILES) entries = entries.slice(0, MAX_INDEXED_FILES);

  const storedFiles = await getStoredIndexFiles({ repoFullName, userId });
  const { changed, unchanged, deleted } = diffAgainstStoredIndex(entries, storedFiles);

  if (deleted.length > 0) {
    await pruneRepoIndexFiles({ repoFullName, userId, filePaths: deleted });
  }

  const fetched = await fetchInBatches(changed, CONCURRENCY, async (entry) => {
    const content = await fetchBlobContent(octokit, owner, repo, entry.sha);
    return { entry, content };
  });

  const knownPaths = new Set(entries.map((e) => e.path));
  const changedGraphEntries = [];

  for (const result of fetched) {
    if (result.status !== "fulfilled" || !result.value.content) continue;
    const { entry, content } = result.value;

    const imports = extractFileImports(content, entry.path)
      .map((imp) => resolveImportInTree(imp, knownPaths))
      .filter(Boolean);

    changedGraphEntries.push({
      file_path: entry.path,
      blob_sha: entry.sha,
      head_snippet: content.split("\n").slice(0, MAX_LINES_PER_FILE).join("\n").slice(0, HEAD_SNIPPET_CHAR_CAP),
      imports,
    });
  }

  // Unchanged files keep their existing imports/snippet from storage — they
  // still need to participate in the reverse-edge (imported_by) pass below,
  // since a newly-changed file might now import one of them.
  const storedByPath = new Map(storedFiles.map((f) => [f.file_path, f]));
  const unchangedGraphEntries = unchanged.map((entry) => {
    const stored = storedByPath.get(entry.path);
    return {
      file_path: entry.path,
      blob_sha: entry.sha,
      head_snippet: stored?.head_snippet ?? null,
      imports: stored?.imports ?? [],
    };
  });

  const allEntries = [...changedGraphEntries, ...unchangedGraphEntries];

  const importedByMap = new Map(allEntries.map((f) => [f.file_path, []]));
  for (const file of allEntries) {
    for (const importedPath of file.imports) {
      importedByMap.get(importedPath)?.push(file.file_path);
    }
  }

  const finalEntries = allEntries.map((f) => ({
    ...f,
    imported_by: importedByMap.get(f.file_path) || [],
    indexed_sha: sha,
  }));

  if (finalEntries.length > 0) {
    await upsertRepoIndexFiles({ repoFullName, userId, files: finalEntries });
  }

  return { fileCount: finalEntries.length, capped };
}

// ─── Consumer-facing context lookup ───

export async function isIndexReady({ repoFullName, userId, sha }) {
  const meta = await getRepoIndexMeta({ repoFullName, userId });
  return !!meta && meta.status === "ready" && meta.indexed_sha === sha;
}

function formatContextChunk(filePath, snippet) {
  if (!snippet) return null;
  // Must keep "(first N lines" intact (no words between "(" and "first") —
  // review-engine.js's chunk-counting log matches on /\/\/ .+ \(first/g.
  return `// ${filePath} (first ${MAX_LINES_PER_FILE} lines, indexed)\n${snippet}`;
}

/**
 * Pure function: depth-2 transitive expansion (imports + imported-by) of
 * each changed file against an in-memory map of all indexed files, formatted
 * as the same chunk string codebase-context.js's live lookup already
 * produces, so review-engine.js's existing chunk-counting log line keeps
 * working unmodified regardless of which path served the context.
 */
export function buildContextFromGraph(changedFilePaths, filesByPath) {
  const relatedPaths = new Set();

  const expand = (fromPaths) => {
    for (const p of fromPaths) {
      const file = filesByPath.get(p);
      if (!file) continue;
      for (const imp of file.imports || []) relatedPaths.add(imp);
      for (const dep of file.imported_by || []) relatedPaths.add(dep);
    }
  };

  expand(changedFilePaths); // hop 1
  expand([...relatedPaths]); // hop 2

  for (const changedPath of changedFilePaths) relatedPaths.delete(changedPath);

  const chunks = [];
  let totalChars = 0;
  for (const p of relatedPaths) {
    const file = filesByPath.get(p);
    const chunk = file && formatContextChunk(p, file.head_snippet);
    if (!chunk) continue;
    if (totalChars + chunk.length > CONTEXT_MAX_TOTAL_CHARS) break;
    chunks.push(chunk);
    totalChars += chunk.length;
  }

  return chunks.length > 0 ? chunks.join("\n\n---\n\n") : "";
}

/**
 * Main export for the review pipeline: returns a context string built from
 * the persisted graph if (and only if) the index is ready for this exact
 * base sha, or null immediately if not — callers fall back to the live
 * one-hop lookup on null, never wait or poll.
 */
export async function getRepoIndexContext({ repoFullName, userId, sha, changedFiles }) {
  const ready = await isIndexReady({ repoFullName, userId, sha });
  if (!ready) return null;

  const storedFiles = await getStoredIndexFiles({ repoFullName, userId });
  if (storedFiles.length === 0) return null;

  const filesByPath = new Map(storedFiles.map((f) => [f.file_path, f]));
  const changedPaths = changedFiles.map((f) => f.filename);

  const context = buildContextFromGraph(changedPaths, filesByPath);
  return context || null;
}
