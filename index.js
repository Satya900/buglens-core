import 'dotenv/config';
import express from "express";
import axios from "axios";
import { GoogleGenerativeAI } from "@google/generative-ai";
import crypto from "crypto";
import { saveReview } from './lib/supabase.js';

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
const model = genAI.getGenerativeModel({ 
  model: "gemini-2.5-flash",
  systemInstruction: "You are a senior tech lead and security auditor. Your goal is high-precision code reviews. \nRULES:\n1. Be extremely cautious with library names (e.g., look for 'lucide-react' vs 'luide'). \n2. Do NOT suggest code that contains typos.\n3. If you see a typo in the original code, suggest the CORRECT package name (e.g., 'lucide-react').\n4. Never hallucinate nonexistent libraries."
});

// Middleware to verify GitHub Webhook signature
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

// Helper to extract structured findings for DB
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
// Capture raw body for signature verification
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

app.post("/webhook", verifySignature, async (req, res) => {
  try {
    const event = req.headers["x-github-event"];

    if (event === "pull_request") {
      const action = req.body.action;

      if (action === "opened" || action === "synchronize") {
        const pr = req.body.pull_request;
        const repoFullName = req.body.repository.full_name;
        const [owner, repoName] = repoFullName.split("/");
        const pull_number = pr.number;

        console.log(`🚀 PR Event [${action.toUpperCase()}] Received: ${repoFullName} #${pull_number}`);

        try {
          const filesUrl = `${pr.url}/files`;
          console.log(`📡 Fetching files from: ${filesUrl}`);
          
          const response = await axios.get(filesUrl, {
            headers: {
              Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
              Accept: "application/vnd.github+json",
            },
            timeout: 10000
          });

          const files = response.data;
          console.log(`📊 Found ${files.length} changed files.`);
          let allComments = [];
          let allReviews = [];
          let allFindings = [];

          for (const file of files) {
            if (file.patch) {
              console.log("📄 Reviewing:", file.filename);

              const prompt = `PR Title: ${pr.title}\nReview this code diff for file ${file.filename}:\n\n${file.patch}\n\nRules: 1. Max 3 issues. 2. Use: [HIGH] for security/critical, [MEDIUM] for logic/bugs, [LOW] for style. 3. Be EXTREMELY precise. 4. Identify the line number (start with [Line XX]). 5. Code suggestions must be valid and directly fix the issue. 6. If no issues, respond: NO_ISSUES. Output format (repeat for each issue): ⚠️ [SEVERITY] [Line XX] [Issue]\n\n\`\`\`suggestion\n[verified fix]\n\`\`\``;

              try {
                const aiResponse = await model.generateContent(prompt);
                const reviewText = aiResponse.response.text();
                
                if (reviewText.includes("NO_ISSUES")) {
                  console.log("⏭ Skipping review for", file.filename, "(no issues)");
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
                    console.log(`✅ Staged inline comment for ${file.filename} at line ${line}`);
                  }
                }
              } catch (aiErr) {
                console.error(`❌ AI Review Failed for ${file.filename}:`, aiErr.message);
              }
            }
          }

          if (allReviews.length > 0 || files.length > 0) {
            const summaryPrompt = `Analyze these file-level reviews and provide a summary:
${allReviews.map((r) => `File: ${r.file}\nReview: ${r.review}`).join("\n\n")}

Decide merge status: APPROVE or REQUEST_CHANGES
Identify the biggest risk.
Concise (max 6 lines).

Output format:
Merge Status: ...
Key Risk: ...
Summary: ...
Recommended Action: ...`;

            try {
              const summaryResponse = await model.generateContent(summaryPrompt);
              const mainSummary = summaryResponse.response.text();
              const decision = mainSummary.includes("REQUEST_CHANGES") ? "REQUEST_CHANGES" : "APPROVE";

              let reviewPosted = false;
              try {
                await axios.post(
                  `https://api.github.com/repos/${owner}/${repoName}/pulls/${pull_number}/reviews`,
                  {
                    body: `🧠 **BugLens PR Summary**\n\n${mainSummary}\n\n---\n_Decision generated based on ${allReviews.length} file-level insights._`,
                    event: decision === "APPROVE" ? "APPROVE" : "REQUEST_CHANGES",
                    comments: allComments,
                  },
                  {
                    headers: {
                      Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
                      Accept: "application/vnd.github+json",
                    },
                  }
                );
                console.log(`✅ Review posted: ${decision}`);
                reviewPosted = true;
              } catch (reviewErr) {
                if (reviewErr.response?.status === 422) {
                  await axios.post(
                    `https://api.github.com/repos/${owner}/${repoName}/pulls/${pull_number}/reviews`,
                    {
                      body: `🧠 **BugLens PR Summary** (Self-Review Mode)\n\n${mainSummary}\n\n---\n_Review generated based on ${allReviews.length} file-level insights._`,
                      event: "COMMENT",
                      comments: allComments,
                    },
                    {
                      headers: {
                        Authorization: `Bearer ${process.env.GITHUB_TOKEN}`,
                        Accept: "application/vnd.github+json",
                      },
                    }
                  );
                  console.log("✅ Review posted as COMMENT (Self-Review)");
                  reviewPosted = true;
                } else {
                  console.error("❌ GitHub Review API error:", reviewErr.message);
                }
              }

              // Always sync to DB if review was posted
              if (reviewPosted) {
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
              }

            } catch (sumErr) {
              console.error("❌ Summary Generation Failed:", sumErr.message);
            }
          }
        } catch (err) {
          console.error("❌ Error processing PR review:", err.message);
          if (err.response) {
            console.error("📌 Error Data:", JSON.stringify(err.response.data, null, 2));
          }
        }
      }
    }

    res.sendStatus(200);
  } catch (globalErr) {
    console.error("⛔ CRITICAL CRASH in Webhook Handler:", globalErr);
    if (!res.headersSent) {
      res.status(500).send("Internal Server Error");
    }
  }
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`🚀 BugLens Core running on ${PORT}`);
});