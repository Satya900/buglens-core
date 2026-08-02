/**
 * file-filters.js
 *
 * Single source of truth for "should this file be excluded from review /
 * indexing" decisions. Previously this logic lived separately in index.js
 * (EXCLUDED_EXTENSIONS, suffix-matched) and review-engine.js
 * (SKIPPED_REVIEW_PATTERNS, root-anchored exact-name regex) and had drifted:
 * review-engine also skipped .min.js/.min.css, which index.js's fetch-time
 * filter did not, and index.js's suffix match caught lockfiles at any path
 * depth (monorepos) while review-engine's anchored regex only matched a
 * root-level lockfile. Consolidated on the broader suffix-match behavior,
 * since lockfiles nested in a subpackage are just as irrelevant to review as
 * a root one.
 */

const EXCLUDED_SUFFIXES = [
  ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", // Media
  ".lock", ".lockb", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", // Lockfiles
  ".bin", ".exe", ".dll", ".so", ".dylib", // Binaries
  ".map", ".woff", ".woff2", ".ttf", ".eot", // Fonts / Source Maps
  ".min.js", ".min.css", // Minified bundles
];

export function isExcludedFile(filename) {
  const lower = filename.toLowerCase();
  return EXCLUDED_SUFFIXES.some((suffix) => lower.endsWith(suffix));
}
