/**
 * codebase-context.js
 *
 * Builds codebase-aware context for AI reviews by:
 *   1. Extracting local imports from each changed file's diff
 *   2. Fetching the first 50 lines of those imported files from GitHub
 *   3. Returning a capped string to inject into the AI prompt
 *
 * Zero-failure design: any GitHub API error → graceful empty return.
 * Never throws. Never blocks the main review pipeline.
 */

import path from 'path';
import { getRepoIndexContext } from './repo-index.js';

const MAX_IMPORTED_FILES = 4;   // max unique imports to fetch per PR
const MAX_LINES_PER_FILE = 50;  // first 50 lines captures exports/types/signatures
const MAX_TOTAL_CHARS    = 6000; // ~1500 tokens hard cap — never burn more than this

/**
 * Extract local import paths from a unified diff patch.
 * Captures: relative imports (./x, ../x) and path alias imports (@/x)
 * Ignores:  node_modules, absolute imports, dynamic imports
 */
function extractLocalImports(patch, filename) {
  if (!patch) return [];

  const dir = path.dirname(filename).replace(/\\/g, '/');

  // Match both `import ... from '...'` and `require('...')` patterns
  const importPattern = /(?:from|require)\s*\(\s*['"](\.[^'"]+|@\/[^'"]+)['"]\s*\)|from\s+['"](\.[^'"]+|@\/[^'"]+)['"]/g;

  const seen   = new Set();
  const result = [];
  let match;

  while ((match = importPattern.exec(patch)) !== null) {
    const raw = match[1] || match[2];
    if (!raw) continue;

    let resolved;
    if (raw.startsWith('@/')) {
      // @/ alias → try both src/ and app/ (Next.js convention)
      resolved = raw.replace('@/', 'src/');
    } else {
      resolved = path.posix.normalize(`${dir}/${raw}`);
    }

    // Strip leading ./
    resolved = resolved.replace(/^\.\//, '');

    if (!seen.has(resolved)) {
      seen.add(resolved);
      result.push(resolved);
    }
    if (result.length >= MAX_IMPORTED_FILES) break;
  }

  return result;
}

/**
 * Generate candidate file paths to try when extension is omitted.
 * TypeScript imports almost always omit extensions.
 */
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

/**
 * Fetch the first N lines of a file from GitHub.
 * Returns null on any error — never throws.
 */
async function fetchFileHead(octokit, owner, repo, filePath, ref) {
  try {
    const { data } = await octokit.repos.getContent({ owner, repo, path: filePath, ref });

    if (data.type !== 'file' || !data.content) return null;

    const full  = Buffer.from(data.content, 'base64').toString('utf8');
    const lines = full.split('\n').slice(0, MAX_LINES_PER_FILE).join('\n');
    return lines;
  } catch {
    return null;
  }
}

/**
 * Try candidate paths in order until one resolves.
 * Returns { path, content } or null.
 */
async function resolveAndFetch(octokit, owner, repo, importPath, ref) {
  for (const candidate of candidatePaths(importPath)) {
    const content = await fetchFileHead(octokit, owner, repo, candidate, ref);
    if (content) return { resolvedPath: candidate, content };
  }
  return null;
}

/**
 * Main export — builds codebase context string for injection into the AI prompt.
 *
 * @param {import('@octokit/rest').Octokit} octokit - Authenticated GitHub client
 * @param {string} repoFullName - e.g. "owner/repo"
 * @param {Array<{filename: string, patch?: string}>} reviewableFiles - PR diff files
 * @param {string} sha - Head commit SHA of the PR
 * @returns {Promise<string>} Context block or empty string
 */
export async function buildCodebaseContext(octokit, repoFullName, reviewableFiles, sha) {
  // Graceful no-ops
  if (!octokit || !repoFullName || !sha || !reviewableFiles?.length) return '';

  const [owner, repo] = repoFullName.split('/');

  // 1. Collect unique import paths across all changed files
  const importedPaths = new Set();
  for (const file of reviewableFiles) {
    for (const imp of extractLocalImports(file.patch || '', file.filename)) {
      importedPaths.add(imp);
      if (importedPaths.size >= MAX_IMPORTED_FILES) break;
    }
    if (importedPaths.size >= MAX_IMPORTED_FILES) break;
  }

  if (importedPaths.size === 0) return '';

  // 2. Fetch all candidate files concurrently (parallel = fast)
  const fetchResults = await Promise.allSettled(
    [...importedPaths].map(imp => resolveAndFetch(octokit, owner, repo, imp, sha))
  );

  // 3. Build context string within token budget
  const chunks    = [];
  let totalChars  = 0;

  for (const result of fetchResults) {
    if (result.status !== 'fulfilled' || !result.value) continue;

    const { resolvedPath, content } = result.value;

    // Skip files that are themselves being reviewed (already in the diff)
    const isInDiff = reviewableFiles.some(f => f.filename === resolvedPath);
    if (isInDiff) continue;

    if (totalChars + content.length > MAX_TOTAL_CHARS) {
      const remaining = MAX_TOTAL_CHARS - totalChars;
      if (remaining > 300) {
        chunks.push(`// ${resolvedPath} (first ${MAX_LINES_PER_FILE} lines, truncated)\n${content.slice(0, remaining)}`);
      }
      break;
    }

    chunks.push(`// ${resolvedPath} (first ${MAX_LINES_PER_FILE} lines)\n${content}`);
    totalChars += content.length;
  }

  if (chunks.length === 0) return '';

  return chunks.join('\n\n---\n\n');
}

/**
 * Consumer-facing entry point used by review-engine.js. Tries the persisted
 * repo-index graph first (lib/repo-index.js) — real cross-file context, not
 * just directly-imported files — and falls back to this file's live one-hop
 * lookup immediately (no polling, no blocking) if the index isn't ready for
 * this exact base sha yet. `sha` here is always pr.base.sha (see index.js),
 * which is what makes both paths safe for fork-originated PRs: it always
 * exists in the upstream repo regardless of where the PR came from.
 *
 * @param {object} params
 * @param {import('@octokit/rest').Octokit} params.octokit
 * @param {string} params.repoFullName
 * @param {string} params.userId - repo owner's user id, for repo_index_* scoping
 * @param {Array<{filename: string, patch?: string}>} params.reviewableFiles
 * @param {string} params.sha - PR base sha
 * @returns {Promise<string>} Context block or empty string
 */
export async function getCodebaseContext({ octokit, repoFullName, userId, reviewableFiles, sha }) {
  const indexed = await getRepoIndexContext({
    repoFullName,
    userId,
    sha,
    changedFiles: reviewableFiles,
  });
  if (indexed) return indexed;

  return buildCodebaseContext(octokit, repoFullName, reviewableFiles, sha);
}
