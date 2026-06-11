// config-reader.js
// Reads and parses .buglens.yml from the root of the repo being reviewed.
// Falls back to dashboard settings if the file does not exist or is invalid.
//
// Supported fields:
//   strictness: "strict" | "balanced" | "lenient"   (default: "balanced")
//   ignore:     string[]                              (glob patterns to skip)
//   shadow:     boolean                               (override dashboard shadow mode)
//   max_files:  number                                (cap files reviewed per PR)
//
// Example .buglens.yml:
//   strictness: strict
//   ignore:
//     - "src/__tests__"
//     - "migrations"
//   max_files: 20

import logger from "./logger.js";

const BUGLENS_CONFIG_PATH = ".buglens.yml";
const VALID_STRICTNESS = new Set(["strict", "balanced", "lenient"]);

/**
 * Fetches and parses .buglens.yml from the target repo via GitHub API.
 * Returns null if the file doesn't exist or can't be parsed.
 */
export async function readRepoBugLensConfig(octokit, owner, repo, ref) {
  try {
    const { data } = await octokit.repos.getContent({
      owner,
      repo,
      path: BUGLENS_CONFIG_PATH,
      ref,
    });

    if (data.type !== "file" || !data.content) return null;

    const raw = Buffer.from(data.content, "base64").toString("utf8");
    return parseConfig(raw, `${owner}/${repo}`);
  } catch (err) {
    // 404 = file doesn't exist — totally normal
    if (err.status !== 404) {
      logger.warn(`Failed to read .buglens.yml from ${owner}/${repo}: ${err.message}`);
    }
    return null;
  }
}

/**
 * Parses raw YAML-like config. Uses a minimal hand-rolled parser to avoid
 * adding a yaml dependency — .buglens.yml is intentionally simple.
 */
function parseConfig(raw, repoName) {
  const config = {};

  try {
    const lines = raw.split("\n");
    let currentKey = null;
    let inList = false;

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;

      // List item
      if (trimmed.startsWith("- ") && inList && currentKey) {
        if (!config[currentKey]) config[currentKey] = [];
        config[currentKey].push(trimmed.slice(2).trim().replace(/['"]/g, ""));
        continue;
      }

      // Key: value pair
      const colonIdx = trimmed.indexOf(":");
      if (colonIdx === -1) continue;

      const key = trimmed.slice(0, colonIdx).trim();
      const value = trimmed.slice(colonIdx + 1).trim();

      inList = value === "";
      currentKey = key;

      if (value !== "") {
        config[key] = coerce(value);
        inList = false;
      }
    }

    return validate(config, repoName);
  } catch (err) {
    logger.warn(`Could not parse .buglens.yml for ${repoName}: ${err.message}`);
    return null;
  }
}

function coerce(value) {
  if (value === "true") return true;
  if (value === "false") return false;
  const num = Number(value);
  if (!isNaN(num) && value !== "") return num;
  return value.replace(/^["']|["']$/g, ""); // strip surrounding quotes
}

function validate(raw, repoName) {
  const config = {};

  if (raw.strictness !== undefined) {
    if (VALID_STRICTNESS.has(raw.strictness)) {
      config.strictness = raw.strictness;
    } else {
      logger.warn(
        `.buglens.yml [${repoName}]: invalid strictness "${raw.strictness}", using dashboard setting`
      );
    }
  }

  if (Array.isArray(raw.ignore) && raw.ignore.length > 0) {
    config.ignorePatterns = raw.ignore.slice(0, 50); // cap at 50 patterns
  }

  if (typeof raw.shadow === "boolean") {
    config.shadow = raw.shadow;
  }

  if (typeof raw.max_files === "number" && raw.max_files > 0) {
    config.maxFiles = Math.min(Math.floor(raw.max_files), 100); // hard cap at 100
  }

  logger.info({ msg: "Loaded .buglens.yml", repo: repoName, config });
  return config;
}

/**
 * Merges repo-file config on top of dashboard config.
 * Repo file wins for any key it defines.
 */
export function mergeConfigs(dashboardConfig, fileConfig) {
  if (!fileConfig) return dashboardConfig;

  return {
    ...dashboardConfig,
    reviewStrictness: fileConfig.strictness ?? dashboardConfig.reviewStrictness,
    shadowMode: fileConfig.shadow ?? dashboardConfig.shadowMode,
    ignorePatterns: fileConfig.ignorePatterns ?? dashboardConfig.ignorePatterns ?? [],
    maxFiles: fileConfig.maxFiles ?? dashboardConfig.maxFiles ?? 50,
  };
}
