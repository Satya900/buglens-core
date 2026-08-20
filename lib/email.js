/**
 * Email notifications via Resend.
 * Requires RESEND_API_KEY and RESEND_FROM_EMAIL environment variables.
 * Sign up at https://resend.com — free tier: 3,000 emails/month.
 *
 * Install: npm install resend
 */

let resendClient = null;

async function getResend() {
  if (!process.env.RESEND_API_KEY) return null;
  if (resendClient) return resendClient;
  try {
    const { Resend } = await import("resend");
    resendClient = new Resend(process.env.RESEND_API_KEY);
    return resendClient;
  } catch {
    return null; // resend not installed — skip silently
  }
}

const FROM = process.env.RESEND_FROM_EMAIL || "BugLens <noreply@buglens.dev>";
const DASHBOARD_URL = process.env.DASHBOARD_URL || "https://buglens.dev";

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Sends a review summary email to the repo owner after a PR review is posted.
 */
export async function sendReviewSummaryEmail({
  toEmail,
  prTitle,
  repoFullName,
  prUrl,
  decision,
  findingsCount,
  riskSummary,
  reviewId,
}) {
  const resend = await getResend();
  if (!resend || !toEmail) return;

  const safeTitle = escapeHtml(prTitle);
  const safeRepo = escapeHtml(repoFullName);
  const safeRisk = escapeHtml(riskSummary || "No critical issues");
  const decisionLabel = decision === "APPROVE" ? "✅ Approved" : "⚠️ Changes Requested";
  const detailUrl = `${DASHBOARD_URL}/reviews/${reviewId}`;
  // Only allow http(s) PR links in the template href.
  const safePrUrl =
    typeof prUrl === "string" && /^https?:\/\//i.test(prUrl) ? prUrl : null;

  try {
    await resend.emails.send({
      from: FROM,
      to: toEmail,
      subject: `BugLens reviewed: ${String(prTitle ?? "").slice(0, 120)} - ${decision}`,
      html: `
        <div style="font-family: monospace; max-width: 600px; margin: 0 auto; background: #0d1117; color: #e6edf3; padding: 32px; border-radius: 8px;">
          <h2 style="color: #22c55e; margin-top: 0;">BugLens Review Complete</h2>
          <p style="color: #8b949e; font-size: 13px; margin-bottom: 24px;">${safeRepo}</p>

          <div style="background: #161b22; border: 1px solid #30363d; border-radius: 6px; padding: 20px; margin-bottom: 20px;">
            <div style="font-size: 16px; font-weight: 600; margin-bottom: 8px;">${safeTitle}</div>
            <div style="font-size: 20px; font-weight: 700; margin-bottom: 12px;">${decisionLabel}</div>
            <div style="font-size: 13px; color: #8b949e;">${Number(findingsCount) || 0} finding(s) · ${safeRisk}</div>
          </div>

          <div style="display: flex; gap: 12px;">
            <a href="${detailUrl}" style="background: #22c55e; color: #000; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-size: 13px; font-weight: 600;">View Full Report</a>
            ${safePrUrl ? `<a href="${escapeHtml(safePrUrl)}" style="background: #21262d; color: #e6edf3; padding: 10px 20px; border-radius: 6px; text-decoration: none; font-size: 13px; border: 1px solid #30363d;">View on GitHub</a>` : ""}
          </div>

          <p style="font-size: 11px; color: #484f58; margin-top: 24px; margin-bottom: 0;">
            You received this because you have BugLens installed. <a href="${DASHBOARD_URL}/settings" style="color: #8b949e;">Manage notifications</a>
          </p>
        </div>
      `,
    });
  } catch (err) {
    // Non-fatal — never let email failure break the review flow
    console.error(`Email send failed for ${repoFullName} PR: ${err.message}`);
  }
}
