/**
 * Cross-file impact for PR summaries.
 *
 * Prefer the persisted import graph (real paths only). Do not ask the model
 * to invent paths: that produced plausible but nonexistent files in reviews.
 * If the index is missing, return [] rather than guessing.
 */

/**
 * Extract a JSON array from model text. Prefers a fenced ```json block,
 * then a balanced [...] scan. Exported for tests.
 */
export function extractJsonArray(responseText) {
  if (!responseText || typeof responseText !== "string") return null;

  const trimmed = responseText.trim();
  if (trimmed === "NONE" || trimmed === "[]") return [];

  const fenced = trimmed.match(/```(?:json)?\s*(\[[\s\S]*?\])\s*```/i);
  if (fenced) {
    try {
      const parsed = JSON.parse(fenced[1]);
      return Array.isArray(parsed) ? parsed : null;
    } catch {
      // fall through
    }
  }

  const start = trimmed.indexOf("[");
  if (start === -1) return null;

  let depth = 0;
  let inString = false;
  let escape = false;
  for (let i = start; i < trimmed.length; i++) {
    const ch = trimmed[i];
    if (inString) {
      if (escape) {
        escape = false;
      } else if (ch === "\\") {
        escape = true;
      } else if (ch === '"') {
        inString = false;
      }
      continue;
    }
    if (ch === '"') {
      inString = true;
      continue;
    }
    if (ch === "[") depth += 1;
    if (ch === "]") {
      depth -= 1;
      if (depth === 0) {
        try {
          const parsed = JSON.parse(trimmed.slice(start, i + 1));
          return Array.isArray(parsed) ? parsed : null;
        } catch {
          return null;
        }
      }
    }
  }

  return null;
}

/**
 * @param {object} opts
 * @param {Array<{ filename: string }>} opts.files - PR changed files
 * @param {Map<string, { imports?: string[], imported_by?: string[] }>|null} opts.knownFilesByPath
 * @returns {string[]} up to 3 real paths that import a changed file
 */
export function identifyImpactedFiles({ files, knownFilesByPath = null }) {
  if (!knownFilesByPath || knownFilesByPath.size === 0) {
    return [];
  }

  const changed = new Set(
    (files || []).map((f) => f.filename).filter(Boolean)
  );
  const impacted = [];

  for (const filename of changed) {
    const entry = knownFilesByPath.get(filename);
    if (!entry) continue;

    for (const dependent of entry.imported_by || []) {
      if (!dependent || changed.has(dependent)) continue;
      if (!knownFilesByPath.has(dependent)) continue;
      if (impacted.includes(dependent)) continue;
      impacted.push(dependent);
      if (impacted.length >= 3) return impacted;
    }
  }

  return impacted;
}

/**
 * Summarizes the cross-file impact for the primary review prompt.
 */
export function buildImpactSummary(impactedFiles) {
  if (!impactedFiles || impactedFiles.length === 0) {
    return "";
  }

  return [
    "",
    "🚧 **CAUTION: Cross-file Impact Detected** 🚧",
    `The following files import changed modules (from the repo index): [${impactedFiles.join(", ")}]`,
    "Consider how these changes break contracts or expectations in these locations.",
    "",
  ].join("\n");
}
