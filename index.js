import "dotenv/config";
import express from "express";
import rateLimit from "express-rate-limit";
import { GoogleGenerativeAI } from "@google/generative-ai";
import crypto from "crypto";
import logger from "./lib/logger.js";
import { initSentry, captureException } from "./lib/sentry.js";
import { createAppAuth } from "@octokit/auth-app";
import { Octokit } from "@octokit/rest";
import {
  getRepoReviewConfig,
  saveReview,
  saveShadowReview,
  checkBillingEligibility,
  incrementUserUsage,
  getLessonsLearned,
  isDeliveryAlreadyProcessed,
  getUserEmailPrefs,
} from "./lib/supabase.js";
import { analyzePullRequest } from "./lib/review-engine.js";
import { buildRepoProfile } from "./lib/repo-profile.js";
import { readRepoBugLensConfig, mergeConfigs } from "./lib/config-reader.js";
import { sendReviewSummaryEmail } from "./lib/email.js";

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

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({
  model: "gemini-2.5-flash",
  systemInstruction:
    "You are a senior tech lead and security auditor. Your goal is high-precision code reviews.\n" +
    "Rules:\n" +
    "1. Review only real issues that are directly supported by the diff.\n" +
    "2. Prioritize security, correctness, and reliability over style.\n" +
    "3. If no actionable issue exists, respond exactly with NO_ISSUES.\n" +
    "4. Include a valid line number in every finding.\n" +
    "5. Code suggestions must be syntactically correct and directly fix the issue.\n" +
    "6. Never hallucinate dependencies or APIs.",
});

async function getAuthenticatedClient(installationId) {
  const auth = createAppAuth({
    appId: process.env.GITHUB_APP_ID,
    privateKey: process.env.GITHUB_PRIVATE_KEY,
    installationId,
  });
  const { token } = await auth({ type: "installation" });
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

const EXCLUDED_EXTENSIONS = [
  ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico", ".pdf", // Media
  ".lock", ".lockb", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", // Lockfiles
  ".bin", ".exe", ".dll", ".so", ".dylib", // Binaries
  ".map", ".woff", ".woff2", ".ttf", ".eot", // Fonts / Source Maps
];

async function fetchPullRequestFiles(octokit, owner, repo, pullNumber) {
  const files = await octokit.paginate(octokit.pulls.listFiles, {
    owner,
    repo,
    pull_number: pullNumber,
    per_page: 100,
  });

  return files.filter((file) => {
    const filename = file.filename.toLowerCase();
    const isExcluded = EXCLUDED_EXTENSIONS.some((ext) => filename.endsWith(ext));
    const isDeleted = file.status === "removed";
    return !isExcluded && !isDeleted;
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

    const bugLensReviews = reviews.filter(
      (r) =>
        (r.user?.type === "Bot" || r.user?.login?.toLowerCase().includes("buglens")) &&
        (r.state === "CHANGES_REQUESTED" || r.state === "APPROVED" || r.state === "COMMENTED")
    );

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

  // Idempotency guard: skip if this exact GitHub delivery was already processed
  if (await isDeliveryAlreadyProcessed(deliveryId)) {
    logger.info(`Skipping duplicate delivery ${deliveryId} for ${repoFullName} #${pullNumber}`);
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

  const billing = await checkBillingEligibility(owner);
  if (!billing.eligible) {
    logger.warn({ msg: "Usage limit reached", owner, tier: billing.tier });
    await octokit.issues.createComment({
      owner,
      repo: repoName,
      issue_number: pullNumber,
      body: `🛡️ **BugLens - Usage Limit Reached**\n\nYou have reached the limit for your current **${billing.tier}** plan. To continue receiving AI code reviews, please upgrade your subscription in the [BugLens Dashboard](https://buglens-next.vercel.app/billing).\n\n*Review scheduled for next month or upon upgrade.*`,
    });
    return;
  }

  // 2. Fetch Lessons (Point 3)
  const lessons = await getLessonsLearned({ repoFullName });

  // Read .buglens.yml from repo root (if present) and merge with dashboard config
  const fileConfig = await readRepoBugLensConfig(octokit, owner, repoName, pr.head.sha);
  const mergedConfig = mergeConfigs(repoConfig, fileConfig);

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
  const isShadowMode = mergedConfig.shadowMode === true;

  const analysis = await analyzePullRequest({
    files,
    model,
    pr,
    repoProfile,
    reviewStrictness,
    lessons,
  });

  logger.info({
    msg: "Analysis complete",
    repo: repoFullName,
    pr: pullNumber,
    files: files.length,
    reviewable: analysis.reviewableFiles.length,
    findings: analysis.findings.length,
    strictness: reviewStrictness,
    shadow: isShadowMode,
  });

  if (isShadowMode) {
    // Shadow mode: run analysis but don't post to GitHub — save to shadow_reviews for dashboard visibility
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
    logger.info(`Shadow review saved for ${repoFullName} #${pullNumber} (not posted to GitHub).`);
  } else {
    const reReviewHeader = isReReview
      ? `> 🔄 **Re-review triggered** — new commits were pushed to this PR by @${pr.user.login}. Previous BugLens review has been dismissed.\n\n`
      : "";

    await octokit.pulls.createReview({
      owner,
      repo: repoName,
      pull_number: pullNumber,
      body: `🧠 **BugLens PR Summary**\n\n${reReviewHeader}${analysis.summary.body}\n\n---\n_Review generated by BugLens AI Bot._`,
      event: analysis.summary.decision,
      comments: analysis.inlineComments.map((comment) => ({
        path: comment.path,
        position: comment.position,
        body: comment.body,
      })),
    });

    logger.info({
      msg: "Review posted",
      repo: repoFullName,
      pr: pullNumber,
      decision: analysis.summary.decision,
      inlineComments: analysis.inlineComments.length,
    });

    // Post GitHub commit status check (green / red checkmark on the commit)
    try {
      const statusState =
        analysis.summary.decision === "APPROVE" ? "success" : "failure";
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
      // Non-fatal — review was posted, status check is bonus
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

    return res.sendStatus(200);
  } catch (error) {
    logger.error({ msg: "Webhook handler crashed", error: error.message });
    captureException(error);
    if (!res.headersSent) {
      return res.status(500).send("Internal Server Error");
    }
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  logger.info({ msg: "BugLens Core running", port: PORT });
});
