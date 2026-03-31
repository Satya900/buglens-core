import 'dotenv/config';
import express from "express";
import axios from "axios";
import { GoogleGenerativeAI } from "@google/generative-ai";
import crypto from "crypto";
import { saveReview } from './lib/supabase.js';
import { createAppAuth } from "@octokit/auth-app";
import { Octokit } from "@octokit/rest";

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ 
  model: "gemini-2.5-flash",
  systemInstruction: "You are a senior tech lead and security auditor. Your goal is high-precision code reviews. \nRULES:\n1. Be extremely cautious with library names (e.g., look for 'lucide-react' vs 'luide'). \n2. Do NOT suggest code that contains typos.\n3. If you see a typo in the original code, suggest the CORRECT package name (e.g., 'lucide-react').\n4. Never hallucinate nonexistent libraries."
});

// Professional GitHub App Auth Setup
async function getAuthenticatedClient(installationId) {
  const auth = createAppAuth({
    appId: process.env.GITHUB_APP_ID,
    privateKey: process.env.GITHUB_PRIVATE_KEY,
    installationId: installationId,
  });
  const { token } = await auth({ type: 'installation' });
  return new Octokit({ auth: token });
}

function verifySignature(req, res, next) {
  const signature = req.headers["x-hub-signature-256"];
  if (!signature) {
    console.error("❌ Missing signature");
    return res.status(401).send("No signature");
  }

  const hmac = crypto.createHmac("sha256", process.env.WEBHOOK_SECRET);
  const digest = "sha256=" + hmac.update(req.rawBody).digest("hex");

  if (!crypto.timingSafeEqual(Buffer.from(signature), Buffer.from(digest))) {
    console.error("❌ Invalid signature");
    return res.status(401).send("Invalid signature");
  }

  next();
}

function getReviewInsights(patch, targetLine = null) {
  const lines = patch.split("\n");
  let currentLineInFile = 0;
  let firstModification = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    if (line.startsWith("@@")) {
      const match = line.match(/\+(\d+)/);
      if (match) {
        currentLineInFile = parseInt(match[1]) - 1;
      }
      continue;
    }

    const isAdded = line.startsWith("+") && !line.startsWith("+++");
    const isUnchanged = !line.startsWith("-") && !line.startsWith("+++");

    if (isAdded || isUnchanged) {
      currentLineInFile++;
    }

    if (isAdded && !firstModification) {
      firstModification = { position: i + 1, line: currentLineInFile };
    }

    if (targetLine && currentLineInFile === targetLine) {
      return { position: i + 1, line: currentLineInFile };
    }
  }

  return firstModification || { position: 1, line: 1 };
}

function parseFinding(review, file, defaultLine) {
  const severityMatch = review.match(/\[(HIGH|MEDIUM|LOW)\]/);
  const lineMatch = review.match(/\[Line (\d+)\]/i);
  const suggestionMatch = review.match(/```suggestion\n([\s\S]*?)```/);
  
  const line = lineMatch ? parseInt(lineMatch[1]) : defaultLine;
  const message = review
    .split('```')[0]
    .replace(/⚠️ \[(HIGH|MEDIUM|LOW)\]/, '')
    .replace(/\[Line \d+\]/i, '')
    .trim();

  return {
    file: file,
    line: line || 0,
    severity: severityMatch ? severityMatch[1] : 'LOW',
    message: message || "View full AI review on GitHub",
    suggestion: suggestionMatch ? suggestionMatch[1].trim() : null
  };
}

const app = express();
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.post("/webhook", verifySignature, async (req, res) => {
  try {
    const event = req.headers["x-github-event"];
    const installationId = req.body.installation?.id;

    // 🚀 CODERABBIT STYLE ONBOARDING: Handle new installs!
    if (event === "installation") {
      const action = req.body.action;
      const repositories = req.body.repositories || [];
      const sender = req.body.sender?.login;

      console.log(`🤖 Installation Event [${action.toUpperCase()}] for user ${sender} (${repositories.length} repos)`);

      if (action === "created" || action === "new_permissions_accepted") {
        for (const repo of repositories) {
          // We'll let the Supabase helper handle the registration/id allocation
          await saveReview({
            repoFullName: repo.full_name,
            registrationOnly: true // New flag we'll handle in supabase.js
          });
          console.log(`📡 Registered: ${repo.full_name}`);
        }
      }
      return res.sendStatus(200);
    }

    if (event === "pull_request" && installationId) {
      const action = req.body.action;

      if (action === "opened" || action === "synchronize") {
        const pr = req.body.pull_request;
        const repoFullName = req.body.repository.full_name;
        const [owner, repoName] = repoFullName.split("/");
        const pull_number = pr.number;

        console.log(`🚀 Professional PR Event [${action.toUpperCase()}] Received: ${repoFullName} #${pull_number}`);

        try {
          const octokit = await getAuthenticatedClient(installationId);
          
          const { data: files } = await octokit.pulls.listFiles({
            owner,
            repo: repoName,
            pull_number,
          });

          console.log(`📊 Found ${files.length} changed files.`);
          let allComments = [];
          let allReviews = [];
          let allFindings = [];

          for (const file of files) {
            if (file.patch) {
              const prompt = `PR Title: ${pr.title}\nReview this code diff for file ${file.filename}:\n\n${file.patch}\n\nRules: 1. Max 3 issues. 2. Use: [HIGH] for security/critical, [MEDIUM] for logic/bugs, [LOW] for style. 3. Be EXTREMELY precise. 4. Identify the line number (start with [Line XX]). 5. Code suggestions must be valid and directly fix the issue. 6. If no issues, respond: NO_ISSUES. Output format (repeat for each issue): ⚠️ [SEVERITY] [Line XX] [Issue]\n\n\`\`\`suggestion\n[verified fix]\n\`\`\``;

              try {
                const aiResponse = await model.generateContent(prompt);
                const reviewText = aiResponse.response.text();
                
                if (reviewText.includes("NO_ISSUES")) {
                  allReviews.push({ file: file.filename, review: "✅ Clean" });
                  continue;
                }

                const findingsArray = reviewText.split('⚠️').filter(f => f.trim().length > 10).map(f => '⚠️' + f);
                allReviews.push({ file: file.filename, review: reviewText });

                for (const singleFinding of findingsArray) {
                  const findingData = parseFinding(singleFinding, file.filename, null);
                  const { position, line } = getReviewInsights(file.patch, findingData.line);
                  
                  findingData.line = line;
                  allFindings.push(findingData);

                  if (position) {
                    allComments.push({
                      path: file.filename,
                      position: position,
                      body: `🧠 **BugLens Review**\n\n${singleFinding}`,
                    });
                  }
                }
              } catch (aiErr) {
                console.error(`❌ AI Review Failed for ${file.filename}:`, aiErr.message);
              }
            }
          }

          if (allReviews.length > 0) {
            const summaryPrompt = `Analyze these file-level reviews and provide a summary:\n${allReviews.map((r) => `File: ${r.file}\nReview: ${r.review}`).join("\n\n")}\n\nDecide merge status: APPROVE or REQUEST_CHANGES\nIdentify the biggest risk.\nConcise (max 6 lines).\n\nOutput format:\nMerge Status: ...\nKey Risk: ...\nSummary: ...\nRecommended Action: ...`;

            try {
              const summaryResponse = await model.generateContent(summaryPrompt);
              const mainSummary = summaryResponse.response.text();
              const decision = mainSummary.includes("REQUEST_CHANGES") ? "REQUEST_CHANGES" : "APPROVE";

              await octokit.pulls.createReview({
                owner,
                repo: repoName,
                pull_number,
                body: `🧠 **BugLens PR Summary**\n\n${mainSummary}\n\n---\n_Review generated by BugLens AI Bot._`,
                event: decision === "APPROVE" ? "APPROVE" : "REQUEST_CHANGES",
                comments: allComments,
              });

              console.log(`✅ Professional review posted via GitHub App: ${decision}`);

              await saveReview({
                repoFullName: repoFullName,
                prNumber: pull_number,
                prTitle: pr.title,
                prAuthor: pr.user.login,
                prUrl: pr.html_url,
                mergeDecision: decision,
                riskSummary: mainSummary.match(/Key Risk:\s*(.*)/)?.[1] || "Reviewed",
                filesReviewed: files.length,
                findings: allFindings,
              });

            } catch (sumErr) {
              console.error("❌ Review Submission Failed:", sumErr.message);
            }
          }
        } catch (err) {
          console.error("❌ Error processing PR review:", err.message);
        }
      }
    }

    res.sendStatus(200);
  } catch (globalErr) {
    console.error("⛔ CRITICAL CRASH in Webhook Handler:", globalErr);
    if (!res.headersSent) res.status(500).send("Internal Server Error");
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 BugLens Core (Bot Mode) running on ${PORT}`);
});