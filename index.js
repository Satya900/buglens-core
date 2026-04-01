import "dotenv/config";
import express from "express";
import { GoogleGenerativeAI } from "@google/generative-ai";
import crypto from "crypto";
import { createAppAuth } from "@octokit/auth-app";
import { Octokit } from "@octokit/rest";
import {
  getRepoReviewConfig,
  saveReview,
  checkBillingEligibility,
  incrementUserUsage,
} from "./lib/supabase.js";
import { analyzePullRequest } from "./lib/review-engine.js";
import { buildRepoProfile } from "./lib/repo-profile.js";

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
    console.error("Missing signature");
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
    console.error("Invalid signature");
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

  console.log(`Installation event [${action?.toUpperCase() || "UNKNOWN"}] for user ${sender}`);

  if (action !== "created" && action !== "new_permissions_accepted") {
    return;
  }

  for (const repo of repositories) {
    await saveReview({
      repoFullName: repo.full_name,
      githubOwner: repo.owner?.login || sender,
      registrationOnly: true,
    });
    console.log(`Registered installation for ${repo.full_name}`);
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

  console.log(`Processing PR event ${action.toUpperCase()} for ${repoFullName} #${pullNumber}`);

  const octokit = await getAuthenticatedClient(installationId);
  const repoConfig = await getRepoReviewConfig({ repoFullName, githubOwner: owner });

  if (repoConfig && repoConfig.isActive === false) {
    console.log(`Skipping inactive repository ${repoFullName}.`);
    return;
  }

  // 1. Billing Gate
  const billing = await checkBillingEligibility(owner);
  if (!billing.eligible) {
    console.log(`User ${owner} has reached their ${billing.tier} plan limit.`);
    await octokit.issues.createComment({
      owner,
      repo: repoName,
      issue_number: pullNumber,
      body: `🛡️ **BugLens - Usage Limit Reached**\n\nYou have reached the limit for your current **${billing.tier}** plan. To continue receiving AI code reviews, please upgrade your subscription in the [BugLens Dashboard](https://buglens-next.vercel.app/billing).\n\n*Review scheduled for next month or upon upgrade.*`,
    });
    return;
  }

  const files = await fetchPullRequestFiles(octokit, owner, repoName, pullNumber);
  if (files.length === 0) return;

  const repoProfile = buildRepoProfile({ repoFullName, files });
  const reviewStrictness = repoConfig?.reviewStrictness || "balanced";
  const shouldPostReview = repoConfig ? repoConfig.isActive !== false : true;

  const analysis = await analyzePullRequest({
    files,
    model,
    pr,
    repoProfile,
    reviewStrictness,
  });

  console.log(
    `Fetched ${files.length} changed files, ${analysis.reviewableFiles.length} eligible for review, ${analysis.findings.length} finding(s). Strictness=${reviewStrictness}, posting=${shouldPostReview}.`
  );

  if (shouldPostReview) {
    await octokit.pulls.createReview({
      owner,
      repo: repoName,
      pull_number: pullNumber,
      body: `🧠 **BugLens PR Summary**\n\n${analysis.summary.body}\n\n---\n_Review generated by BugLens AI Bot._`,
      event: analysis.summary.decision,
      comments: analysis.inlineComments.map((comment) => ({
        path: comment.path,
        position: comment.position,
        body: comment.body,
      })),
    });

    console.log(
      `Posted ${analysis.summary.decision} review with ${analysis.inlineComments.length} inline comment(s).`
    );

    // 2. Persist Review Data
    await saveReview({
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

    // 3. Track Usage for Billing
    await incrementUserUsage(owner);
  } else {
    console.log(`Review was analyzed but not posted to GitHub for ${repoFullName}.`);
  }
}

const app = express();
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

app.post("/webhook", verifySignature, async (req, res) => {
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
      await handlePullRequestEvent(payload);
    }

    return res.sendStatus(200);
  } catch (error) {
    console.error("Webhook handler crashed:", error);
    if (!res.headersSent) {
      return res.status(500).send("Internal Server Error");
    }
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`BugLens Core running on ${PORT}`);
});
