import "dotenv/config";
import express from "express";
import rateLimit from "express-rate-limit";
import crypto from "crypto";
import logger from "./lib/logger.js";
import { initSentry, captureException } from "./lib/sentry.js";
import { createAppAuth } from "@octokit/auth-app";
import { Octokit } from "@octokit/rest";
import {
  getRepoReviewConfig,
  saveReview,
  checkBillingEligibility,
  incrementUserUsage,
  getLessonsLearned,
  isDeliveryAlreadyProcessed,
  getUserEmailPrefs,
  saveShadowReview,
  tryAcquireIndexLock,
  markIndexReady,
  markIndexFailed,
  tryClaimDelivery,
} from "./lib/supabase.js";
import { analyzePullRequest } from "./lib/review-engine.js";
import { buildRepoProfile } from "./lib/repo-profile.js";
import { readRepoBugLensConfig, mergeConfigs } from "./lib/config-reader.js";
import { isExcludedFile } from "./lib/file-filters.js";
import { buildFullRepoIndex } from "./lib/repo-index.js";
import { sendReviewSummaryEmail } from "./lib/email.js";
import { createModel } from "./lib/ai-provider.js";

const REQUIRED_ENV_VARS = [
  "GEMINI_API_KEY",
  "GITHUB_APP_ID",
  "GITHUB_PRIVATE_KEY",
  "SUPABASE_URL",
  "SUPABASE_SERVICE_ROLE_KEY",
  "WEBHOOK_SECRET",
];

function validateEnvironment() {
  const missing = REQUIRED_ENV_VARS.filter((name) => !process.env[name]);
  if (missing.length > 0) {
    throw new Error(`Missing required environment variables: ${missing.join(", ")}`);
  }
}

validateEnvironment();
await initSentry();

async function getAuthenticatedClient(installationId) {
  const auth = createAppAuth({
    appId: process.env.GITHUB_APP_ID,
    privateKey: process.env.GITHUB_PRIVATE_KEY,
    installationId,
  });
  const { token } = await auth({ type: "installation" });
  return new Octokit({ auth: token });
}

/**
 * App-level (JWT) authenticated client — used only to resolve which
 * installation owns a given repo when we don't already have a live webhook
 * payload to pull installation.id from (the /internal/index-repo trigger
 * on repo connect has no such payload).
 */
async function getAppLevelClient() {
  const auth = createAppAuth({
    appId: process.env.GITHUB_APP_ID,
    privateKey: process.env.GITHUB_PRIVATE_KEY,
  });
  const { token } = await auth({ type: "app" });
  return new Octokit({ auth: token });
}

function verifySignature(req, res, next) {
  const signature = req.headers["x-hub-signature-256"];
  if (!signature) {
    logger.warn("Missing signature");
    return res.status(401).send("No signature");
  }

  const hmac = crypto.createHmac("sha256", process.env.WEBHOOK_SECRET);
  const digest = `sha256=${hmac.update(req.rawBody).digest("hex")}`;
  const signatureBuffer = Buffer.from(signature, "utf8");
  const digestBuffer = Buffer.from(digest, "utf8");

  if (
    signatureBuffer.length !== digestBuffer.length ||
    !crypto.timingSafeEqual(signatureBuffer, digestBuffer)
  ) {
    logger.warn("Invalid signature");
    return res.status(401).send("Invalid signature");
  }

  next();
}

async function fetchPullRequestFiles(octokit, owner, repo, pullNumber) {
  const files = await octokit.paginate(octokit.pulls.listFiles, {
    owner,
    repo,
    pull_number: pullNumber,
    per_page: 100,
  });

  return files.filter((file) => {
    const isDeleted = file.status === "removed";
    return !isExcludedFile(file.filename) && !isDeleted;
  });
}

async function handleInstallationEvent(payload) {
  const action = payload.action;
  const repositories = payload.repositories || [];
  const sender = payload.sender?.login;

  logger.info(`Installation event [${action?.toUpperCase() || "UNKNOWN"}] for user ${sender}`);

  if (action !== "created" && action !== "new_permissions_accepted") {
    return;
  }

  for (const repo of repositories) {
    await saveReview({
      repoFullName: repo.full_name,
      githubOwner: repo.owner?.login || sender,
      registrationOnly: true,
    });
    logger.info(`Registered installation for ${repo.full_name}`);
  }
}

/**
 * Shared build->mark sequence for both the push-triggered and connect-
 * triggered indexing paths. Caller must already hold the index lock
 * (tryAcquireIndexLock) before calling this.
 */
async function runRepoIndex({ octokit, repoFullName, userId, sha }) {
  try {
    const result = await buildFullRepoIndex({ octokit, repoFullName, userId, sha });
    await markIndexReady({ repoFullName, userId, sha, ...result });
    logger.info({ msg: "Repo index ready", repo: repoFullName, sha, ...result });
  } catch (err) {
    await markIndexFailed({ repoFullName, userId, error: err.message });
    logger.warn({ msg: "Repo index failed", repo: repoFullName, error: err.message });
  }
}

/**
 * Push-triggered reindexing. Default-branch pushes only — reindexing every
 * branch of every open PR would multiply GitHub API cost for no benefit,
 * since PR review itself always uses the live diff for changed files
 * regardless of what's indexed.
 */
async function handlePushEvent(payload) {
  if (payload.ref !== `refs/heads/${payload.repository.default_branch}`) return;
  if (await isDeliveryAlreadyProcessed(payload.deliveryId)) return;
  if (!(await tryClaimDelivery(payload.deliveryId))) return;

  const repoFullName = payload.repository.full_name;
  const [owner] = repoFullName.split("/");

  const repoConfig = await getRepoReviewConfig({ repoFullName, githubOwner: owner });
  if (!repoConfig || repoConfig.isActive === false) return;

  const locked = await tryAcquireIndexLock({ repoFullName, userId: repoConfig.userId });
  if (!locked) return; // already indexing — a later push re-triggers at its own sha

  const octokit = await getAuthenticatedClient(payload.installation.id);
  await runRepoIndex({ octokit, repoFullName, userId: repoConfig.userId, sha: payload.after });
}

/**
 * Finds and dismisses any existing BugLens reviews on the PR so the new
 * re-review is the only one visible. Only called on "synchronize" events.
 */
async function dismissPreviousBugLensReviews(octokit, owner, repo, pullNumber) {
  try {
    const reviews = await octokit.paginate(octokit.pulls.listReviews, {
      owner,
      repo,
      pull_number: pullNumber,
      per_page: 50,
    });

    // Only dismiss our own app reviews. Matching any Bot would wipe Dependabot,
    // CodeRabbit, Renovate, etc. on synchronize.
    const bugLensReviews = reviews.filter((r) => {
      const login = r.user?.login?.toLowerCase() || "";
      const isBugLens =
        login.includes("buglens") ||
        login === process.env.GITHUB_APP_SLUG?.toLowerCase();
      const dismissable =
        r.state === "CHANGES_REQUESTED" ||
        r.state === "APPROVED" ||
        r.state === "COMMENTED";
      return isBugLens && dismissable;
    });

    for (const review of bugLensReviews) {
      try {
        await octokit.pulls.dismissReview({
          owner,
          repo,
          pull_number: pullNumber,
          review_id: review.id,
          message: "Dismissed — BugLens is re-reviewing due to new commits pushed to this PR.",
        });
        logger.info(`Dismissed previous BugLens review ${review.id} on ${owner}/${repo}#${pullNumber}`);
      } catch (err) {
        // Dismissing can fail if review is already dismissed or in PENDING state — not fatal
        logger.warn(`Could not dismiss review ${review.id}: ${err.message}`);
      }
    }
  } catch (err) {
    logger.warn(`dismissPreviousBugLensReviews failed: ${err.message}`);
  }
}

async function handlePullRequestEvent(payload) {
  const installationId = payload.installation?.id;
  const action = payload.action;

  if (!installationId || (action !== "opened" && action !== "synchronize")) {
    return;
  }

  const pr = payload.pull_request;
  const repoFullName = payload.repository.full_name;
  const [owner, repoName] = repoFullName.split("/");
  const pullNumber = pr.number;
  const deliveryId = payload.deliveryId;
  const isReReview = action === "synchronize";

  // Idempotency: claim this delivery before any expensive work so GitHub
  // retries that arrive while the first run is in flight are dropped.
  if (await isDeliveryAlreadyProcessed(deliveryId)) {
    logger.info(`Skipping duplicate delivery ${deliveryId} for ${repoFullName} #${pullNumber}`);
    return;
  }
  if (!(await tryClaimDelivery(deliveryId))) {
    logger.info(`Skipping already-claimed delivery ${deliveryId} for ${repoFullName} #${pullNumber}`);
    return;
  }

  logger.info(`Processing PR event ${action.toUpperCase()} for ${repoFullName} #${pullNumber}`);

  const octokit = await getAuthenticatedClient(installationId);

  // On push to open PR: dismiss old BugLens reviews before posting the new one
  if (isReReview) {
    await dismissPreviousBugLensReviews(octokit, owner, repoName, pullNumber);
  }

  const repoConfig = await getRepoReviewConfig({ repoFullName, githubOwner: owner });

  if (!repoConfig) {
    logger.warn(`Skipping: Repository ${repoFullName} is not registered or active in the dashboard.`);
    return;
  }

  if (repoConfig.isActive === false) {
    logger.warn(`Skipping inactive repository ${repoFullName}.`);
    return;
  }

  // Read .buglens.yml from repo root (if present) and merge with dashboard config.
  // Done before the billing check so shadowMode is known before we might post a
  // "usage limit reached" comment — shadow mode must produce zero GitHub activity.
  const fileConfig = await readRepoBugLensConfig(octokit, owner, repoName, pr.head.sha);
  const mergedConfig = mergeConfigs(repoConfig, fileConfig);

  const billing = await checkBillingEligibility(owner);
  if (!billing.eligible) {
    logger.warn({ msg: "Usage limit reached", owner, tier: billing.tier });
    if (!mergedConfig.shadowMode) {
      await octokit.issues.createComment({
        owner,
        repo: repoName,
        issue_number: pullNumber,
        body: `🛡️ **BugLens - Usage Limit Reached**\n\nYou have reached the limit for your current **${billing.tier}** plan. To continue receiving AI code reviews, please upgrade your subscription in the [BugLens Dashboard](${(process.env.DASHBOARD_URL || "https://buglens.app").replace(/\/+$/, "")}/billing).\n\n*Review scheduled for next month or upon upgrade.*`,
      });
    }
    return;
  }

  // Select AI model based on billing tier
  const model = createModel(billing.tier);
  logger.info({ msg: "AI provider selected", tier: billing.tier, repo: repoFullName });

  // 2. Fetch Lessons (Point 3)
  const lessons = await getLessonsLearned({ repoFullName, userId: repoConfig.userId });

  let files = await fetchPullRequestFiles(octokit, owner, repoName, pullNumber);
  if (files.length === 0) return;

  // Apply ignore patterns from .buglens.yml
  if (mergedConfig.ignorePatterns?.length > 0) {
    const ignored = mergedConfig.ignorePatterns;
    files = files.filter((f) => {
      return !ignored.some((pattern) => {
        // Simple glob: support ** prefix/suffix and exact match
        if (pattern.startsWith("**/")) {
          const suffix = pattern.slice(3);
          return f.filename.endsWith(suffix) || f.filename.includes(`/${suffix}`);
        }
        if (pattern.endsWith("/**")) {
          const prefix = pattern.slice(0, -3);
          return f.filename.startsWith(prefix);
        }
        return f.filename === pattern || f.filename.endsWith(`/${pattern}`);
      });
    });
    if (files.length === 0) {
      logger.info(`All files ignored by .buglens.yml patterns for ${repoFullName} #${pullNumber}`);
      return;
    }
  }

  // Apply max_files cap from .buglens.yml
  if (mergedConfig.maxFiles && files.length > mergedConfig.maxFiles) {
    logger.info(`Capping files from ${files.length} to ${mergedConfig.maxFiles} per .buglens.yml`);
    files = files.slice(0, mergedConfig.maxFiles);
  }

  const repoProfile = buildRepoProfile({ repoFullName, files });
  const reviewStrictness = mergedConfig.reviewStrictness || "balanced";

  const analysis = await analyzePullRequest({
    files,
    model,
    pr,
    repoProfile,
    reviewStrictness,
    lessons,
    octokit,
    repoFullName,
    userId: repoConfig.userId,
    // Used only for the codebase-context lookup (fetching imported files'
    // content via the GitHub API against `repoFullName`, which is always the
    // base/upstream repo). pr.head.sha only exists in the base repo for
    // same-repo branch PRs — for fork-originated PRs it's a commit in the
    // contributor's fork, so fetching it against the upstream repo silently
    // fails and codebase context degrades to empty. pr.base.sha always
    // exists in the upstream repo regardless of PR origin.
    sha: pr.base.sha,
  });

  logger.info({
    msg: "Analysis complete",
    repo: repoFullName,
    pr: pullNumber,
    files: files.length,
    reviewable: analysis.reviewableFiles.length,
    findings: analysis.findings.length,
    strictness: reviewStrictness,
  });

  if (mergedConfig.shadowMode) {
    await saveShadowReview({
      repoFullName,
      prNumber: pullNumber,
      prTitle: pr.title,
      prAuthor: pr.user.login,
      prUrl: pr.html_url,
      mergeDecision: analysis.summary.decision,
      riskSummary: analysis.summary.riskSummary,
      filesReviewed: analysis.reviewableFiles.length,
      findings: analysis.findings,
      repoProfile,
      deliveryId,
    });

    logger.info({
      msg: "Shadow review saved — no GitHub activity",
      repo: repoFullName,
      pr: pullNumber,
      decision: analysis.summary.decision,
      findings: analysis.findings.length,
    });

    // Shadow reviews still run the full AI pipeline, so they count against usage.
    await incrementUserUsage(owner);
    return;
  }

  const reReviewHeader = isReReview
    ? `> 🔄 **Re-review triggered** — new commits were pushed to this PR by @${pr.user.login}. Previous BugLens review has been dismissed.\n\n`
    : "";

  await octokit.pulls.createReview({
    owner,
    repo: repoName,
    pull_number: pullNumber,
    body: `🧠 **BugLens PR Summary**\n\n${reReviewHeader}${analysis.summary.body}\n\n---\n_Review generated by BugLens AI Bot._`,
    event: analysis.summary.decision,
    comments: analysis.inlineComments
      .filter((comment) => comment.line > 0 || comment.position > 0)
      .map((comment) => {
        if (comment.line > 0) {
          return {
            path: comment.path,
            line: comment.line,
            side: "RIGHT",
            body: comment.body,
          };
        }
        return {
          path: comment.path,
          position: comment.position,
          body: comment.body,
        };
      }),
  });

  logger.info({
    msg: "Review posted",
    repo: repoFullName,
    pr: pullNumber,
    decision: analysis.summary.decision,
    inlineComments: analysis.inlineComments.length,
  });

  // Post GitHub commit status check
  try {
    const statusState = analysis.summary.decision === "APPROVE" ? "success" : "failure";
    const highCount = analysis.findings.filter((f) => f.severity === "HIGH").length;
    const statusDescription =
      statusState === "success"
        ? `BugLens: No blocking issues found`
        : `BugLens: ${highCount} HIGH severity issue${highCount !== 1 ? "s" : ""} — review required`;

    await octokit.repos.createCommitStatus({
      owner,
      repo: repoName,
      sha: pr.head.sha,
      state: statusState,
      description: statusDescription,
      context: "BugLens AI Review",
      target_url: `${process.env.DASHBOARD_URL || "https://buglens.app"}/reviews`,
    });
    logger.info(`Commit status posted: ${statusState} for ${repoFullName}@${pr.head.sha}`);
  } catch (statusErr) {
    logger.warn(`Failed to post commit status: ${statusErr.message}`);
  }

  const savedReview = await saveReview({
    repoFullName,
    githubOwner: owner,
    prNumber: pullNumber,
    prTitle: pr.title,
    prAuthor: pr.user.login,
    prUrl: pr.html_url,
    mergeDecision: analysis.summary.decision,
    riskSummary: analysis.summary.riskSummary,
    filesReviewed: analysis.reviewableFiles.length,
    findings: analysis.findings,
    deliveryId,
  });

  await incrementUserUsage(owner);

  // Send email notification to repo owner (respects user preference)
  if (savedReview?.id) {
    const prefs = await getUserEmailPrefs(owner);
    if (prefs?.email && prefs.emailNotifications) {
      await sendReviewSummaryEmail({
        toEmail: prefs.email,
        prTitle: pr.title,
        repoFullName,
        prUrl: pr.html_url,
        decision: analysis.summary.decision,
        findingsCount: analysis.findings.length,
        riskSummary: analysis.summary.riskSummary,
        reviewId: savedReview.id,
      });
    }
  }
}

const app = express();
app.set('trust proxy', 1); // trust Render/Railway reverse proxy for rate limiting
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

// Rate limit: max 30 webhook calls per minute per IP.
const webhookLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: "Too many requests",
});

app.get("/health", (_req, res) => {
  res.json({ status: "ok", timestamp: new Date().toISOString() });
});

app.post("/webhook", webhookLimiter, verifySignature, async (req, res) => {
  try {
    const event = req.headers["x-github-event"];
    const payload = {
      ...req.body,
      deliveryId: req.headers["x-github-delivery"],
    };

    if (event === "installation") {
      await handleInstallationEvent(payload);
      return res.sendStatus(200);
    }

    if (event === "pull_request") {
      res.sendStatus(200);
      setImmediate(async () => {
        try {
          await handlePullRequestEvent(payload);
        } catch (error) {
          logger.error({ msg: "Async PR review crashed", error: error.message });
          captureException(error, { deliveryId: payload.deliveryId });
        }
      });
      return;
    }

    if (event === "push") {
      res.sendStatus(200);
      setImmediate(async () => {
        try {
          await handlePushEvent(payload);
        } catch (error) {
          logger.error({ msg: "Async repo index crashed", error: error.message });
          captureException(error, { deliveryId: payload.deliveryId });
        }
      });
      return;
    }

    return res.sendStatus(200);
  } catch (error) {
    logger.error({ msg: "Webhook handler crashed", error: error.message });
    captureException(error);
    if (!res.headersSent) {
      return res.status(500).send("Internal Server Error");
    }
  }
});

// ── Internal: trigger an initial index when a repo is first connected ───────
// Called by buglens-next right after a repo is registered, so new users get
// context benefit from their very first PR instead of waiting for someone to
// push to the default branch. Authenticated via the same shared WEBHOOK_SECRET
// both apps already rely on — no live webhook payload exists for this
// trigger, so the installation ID is resolved via the GitHub Apps (JWT) API
// instead of pulled off a payload.
function isValidInternalSecret(provided) {
  if (!provided || !process.env.WEBHOOK_SECRET) return false;
  const providedBuf = Buffer.from(provided, "utf8");
  const expectedBuf = Buffer.from(process.env.WEBHOOK_SECRET, "utf8");
  return providedBuf.length === expectedBuf.length && crypto.timingSafeEqual(providedBuf, expectedBuf);
}

app.post("/internal/index-repo", async (req, res) => {
  if (!isValidInternalSecret(req.headers["x-webhook-secret"])) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  const { repoFullName } = req.body ?? {};
  if (!repoFullName) {
    return res.status(400).json({ error: "repoFullName is required" });
  }

  res.sendStatus(202); // accepted — indexing runs async, this is best-effort

  setImmediate(async () => {
    try {
      const [owner, repoName] = repoFullName.split("/");

      const repoConfig = await getRepoReviewConfig({ repoFullName, githubOwner: owner });
      if (!repoConfig || repoConfig.isActive === false) return;

      const locked = await tryAcquireIndexLock({ repoFullName, userId: repoConfig.userId });
      if (!locked) return;

      const appClient = await getAppLevelClient();
      const { data: installation } = await appClient.apps.getRepoInstallation({ owner, repo: repoName });
      const octokit = await getAuthenticatedClient(installation.id);

      const { data: repoData } = await octokit.repos.get({ owner, repo: repoName });
      const { data: branch } = await octokit.repos.getBranch({
        owner,
        repo: repoName,
        branch: repoData.default_branch,
      });

      await runRepoIndex({ octokit, repoFullName, userId: repoConfig.userId, sha: branch.commit.sha });
    } catch (error) {
      logger.error({ msg: "Initial repo index crashed", repo: repoFullName, error: error.message });
      captureException(error, { repoFullName });
    }
  });
});


// ── DEV-ONLY: AI model test endpoint ─────────────────────────────────────────
// POST /dev/test-ai  — Body: { "model": "free"|"pro"|"qwen"|"gemma", "prompt": "..." }
// Requires ENABLE_DEV_AI_TEST=1 AND x-webhook-secret matching WEBHOOK_SECRET.
// NODE_ENV alone is not enough; a mis-set production env would otherwise expose
// an unauthenticated LLM proxy.
if (process.env.ENABLE_DEV_AI_TEST === "1" && process.env.NODE_ENV !== "production") {
  const OPENROUTER_TEST_MODELS = {
    gemma: "google/gemma-4-31b-it:free",
    qwen:  "qwen/qwen3-coder:free",
  };

  app.post("/dev/test-ai", async (req, res) => {
    if (!isValidInternalSecret(req.headers["x-webhook-secret"])) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    const { model: modelKey = "free", prompt } = req.body ?? {};
    if (!prompt) return res.status(400).json({ error: "prompt is required" });

    const startTime = Date.now();
    try {
      // Direct single-model test (gemma / qwen)
      if (modelKey === "gemma" || modelKey === "qwen") {
        const OpenAI = (await import("openai")).default;
        const client = new OpenAI({
          baseURL: "https://openrouter.ai/api/v1",
          apiKey: process.env.OPENROUTER_API_KEY,
          defaultHeaders: { "HTTP-Referer": "https://buglens.app", "X-Title": "BugLens" },
        });
        const modelId = OPENROUTER_TEST_MODELS[modelKey];
        const label = modelKey === "gemma" ? "OpenRouter/gemma-4-31b-it:free" : "OpenRouter/qwen3-coder:free";
        const completion = await client.chat.completions.create({
          model: modelId,
          messages: [
            { role: "system", content: "You are a senior code reviewer." },
            { role: "user", content: prompt },
          ],
          temperature: 0.1,
          max_tokens: 1024,
        });
        const text = completion.choices?.[0]?.message?.content?.trim() ?? "";
        return res.json({
          provider: label,
          model_id: modelId,
          response: text,
          tokens: completion.usage ?? null,
          latency_ms: Date.now() - startTime,
        });
      }

      // Full chain test (free / pro)
      const testModel = createModel(modelKey === "pro" ? "PRO" : "FREE");
      const label = modelKey === "pro" ? "PRO (primary model)" : "FREE (Gemma via OpenRouter)";
      const result = await testModel.generateContent(prompt);
      return res.json({
        provider: label,
        response: result.response.text(),
        latency_ms: Date.now() - startTime,
      });

    } catch (err) {
      return res.status(500).json({
        error: err.message,
        status: err?.status ?? null,
        latency_ms: Date.now() - startTime,
      });
    }
  });

  logger.info("DEV endpoint active: POST /dev/test-ai (secret required)");
}

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  logger.info({ msg: "BugLens Core running", port: PORT });
});
