/**
 * Identifies which files outside the PR diff are likely impacted by the changes in the PR.
 * In a 2026 scenario, this uses the AI model's global knowledge of common patterns and
 * the context of file paths to predict cross-file regression risks.
 */
export async function identifyImpactedFiles({ model, pr, files }) {
  const fileNames = files.map((f) => f.filename).join(", ");
  const prompt = [
    `PR Title: ${pr.title}`,
    `Changes in: [${fileNames}]`,
    "Evaluate these changes and identify up to 3 files or modules *outside* this list that are likely impacted by these changes.",
    "Rules:",
    "1. Focus on files that depend on the modified modules (e.g., consumers of updated APIs).",
    "2. If no clear impact exists, respond with NONE.",
    "3. Respond with a JSON array of file paths. Example: [\"src/lib/auth.js\", \"app/layout.tsx\"]",
  ].join("\n");

  try {
    const aiResponse = await model.generateContent(prompt);
    const responseText = aiResponse.response.text().trim();

    if (responseText === "NONE") {
      return [];
    }

    // Attempt to extract JSON array
    const match = responseText.match(/\[.*\]/s);
    if (match) {
      const paths = JSON.parse(match[0]);
      return Array.isArray(paths) ? paths : [];
    }
  } catch (error) {
    console.warn(`Impact analysis failed: ${error.message}`);
  }

  return [];
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
    `The following upstream components might be affected by these changes: [${impactedFiles.join(", ")}]`,
    "Consider how these changes break contracts or expectations in these locations.",
    "",
  ].join("\n");
}
