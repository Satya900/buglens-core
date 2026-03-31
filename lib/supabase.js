import { createClient } from "@supabase/supabase-js";

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);

async function ensureRepoRecord({ repoFullName, githubOwner }) {
  const { data: repos, error: repoError } = await supabase
    .from("repos")
    .select("user_id, id, total_reviews, is_active, shadow_mode, review_strictness, auto_post_reviews")
    .eq("repo_full_name", repoFullName);

  let repo = repos && repos.length > 0 ? repos[0] : null;

  if (repoError) {
    console.warn(`Repo lookup error for ${repoFullName}: ${repoError.message}`);
  }

  if (repo) {
    return repo;
  }

  console.log(`Repo ${repoFullName} not found. Looking up dashboard profile for ${githubOwner}...`);

  const { data: ownerProfile, error: profileLookupError } = await supabase
    .from("profiles")
    .select("id")
    .eq("github_username", githubOwner)
    .single();

  if (profileLookupError || !ownerProfile) {
    console.error(`Dashboard profile for '${githubOwner}' was not found.`);
    return null;
  }

  const { data: newRepo, error: createRepoError } = await supabase
    .from("repos")
    .insert({
      user_id: ownerProfile.id,
      repo_full_name: repoFullName,
      is_active: true,
      shadow_mode: false,
      review_strictness: "balanced",
      auto_post_reviews: true,
      created_at: new Date().toISOString(),
    })
    .select()
    .single();

  if (createRepoError) {
    console.error(`Auto-onboarding failed for ${repoFullName}: ${createRepoError.message}`);
    return null;
  }

  return newRepo;
}

async function findExistingRecentReview({
  repoFullName,
  prNumber,
  prUrl,
  mergeDecision,
  riskSummary,
  findingsCount,
}) {
  const { data, error } = await supabase
    .from("reviews")
    .select("id, created_at")
    .eq("repo_full_name", repoFullName)
    .eq("pr_number", prNumber)
    .eq("pr_url", prUrl)
    .eq("merge_decision", mergeDecision)
    .eq("risk_summary", riskSummary)
    .eq("findings_count", findingsCount)
    .order("created_at", { ascending: false })
    .limit(1);

  if (error || !data || data.length === 0) {
    return null;
  }

  const [review] = data;
  const createdAt = new Date(review.created_at).getTime();
  const tenMinutesAgo = Date.now() - 10 * 60 * 1000;

  return createdAt >= tenMinutesAgo ? review : null;
}

export async function saveReview({
  repoFullName,
  githubOwner,
  prNumber,
  prTitle,
  prAuthor,
  prUrl,
  mergeDecision,
  riskSummary,
  filesReviewed,
  findings = [],
  registrationOnly = false,
  deliveryId,
}) {
  console.log(`Connecting to Supabase for ${repoFullName} (owner: ${githubOwner})`);

  try {
    const repo = await ensureRepoRecord({ repoFullName, githubOwner });
    if (!repo) {
      return;
    }

    if (registrationOnly) {
      return repo;
    }

    const existingReview = await findExistingRecentReview({
      repoFullName,
      prNumber,
      prUrl,
      mergeDecision,
      riskSummary,
      findingsCount: findings.length,
    });

    if (existingReview) {
      console.log(
        `Skipping duplicate review insert for ${repoFullName} #${prNumber}. Existing review ${existingReview.id} is recent.`
      );
      return existingReview;
    }

    const { data: review, error: reviewError } = await supabase
      .from("reviews")
      .insert({
        user_id: repo.user_id,
        repo_full_name: repoFullName,
        pr_number: prNumber,
        pr_title: prTitle,
        pr_author: prAuthor,
        pr_url: prUrl,
        merge_decision: mergeDecision,
        risk_summary: riskSummary,
        files_reviewed: filesReviewed,
        findings_count: findings.length,
        created_at: new Date().toISOString(),
      })
      .select()
      .single();

    if (reviewError) {
      console.error("Review insert failed:", reviewError.message);
      return;
    }

    if (findings.length > 0) {
      const findingsPayload = findings.map((finding) => ({
        review_id: review.id,
        file_path: finding.file,
        line_number: finding.line || 1,
        severity: finding.severity || "LOW",
        message: finding.message,
        suggestion: finding.suggestion,
        feedback: finding.source === "rule" ? "deterministic_check" : null,
        source: finding.source || "ai",
        category: finding.category || "general",
        rule_id: finding.ruleId || null,
        confidence: finding.confidence ?? null,
      }));

      const { error: findingsError } = await supabase.from("findings").insert(findingsPayload);
      if (findingsError) {
        console.error("Finding insert failed:", findingsError.message);
      }
    }

    const nextTotalReviews = Number.isFinite(repo.total_reviews) ? repo.total_reviews + 1 : 1;
    const { error: updateError } = await supabase
      .from("repos")
      .update({
        last_review_at: new Date().toISOString(),
        total_reviews: nextTotalReviews,
      })
      .eq("repo_full_name", repoFullName);

    if (updateError) {
      console.warn(`Failed to update repo stats for ${repoFullName}: ${updateError.message}`);
    }

    console.log(
      `Review for PR #${prNumber} synced to Supabase${deliveryId ? ` (delivery ${deliveryId})` : ""}.`
    );
    return review;
  } catch (error) {
    console.error("saveReview crashed:", error.message);
  }
}

export async function getRepoReviewConfig({ repoFullName, githubOwner }) {
  try {
    const repo = await ensureRepoRecord({ repoFullName, githubOwner });
    if (!repo) {
      return null;
    }

    return {
      repoFullName,
      isActive: repo.is_active !== false,
      reviewStrictness: repo.review_strictness || "balanced",
      userId: repo.userId, // This was repo.user_id in some places, ensure consistency
    };
  } catch (error) {
    console.error("getRepoReviewConfig crashed:", error.message);
    return null;
  }
}

/**
 * Checks if a user is eligible for a review based on their tier and usage.
 */
export async function checkBillingEligibility(githubOwner) {
  try {
    const { data: profile, error } = await supabase
      .from("profiles")
      .select("subscription_tier, current_usage, usage_limit")
      .eq("github_username", githubOwner)
      .single();

    if (error || !profile) return { eligible: true }; // Fallback to safe

    if (profile.subscription_tier === "FREE" && profile.current_usage >= profile.usage_limit) {
      return { eligible: false, tier: "FREE", limit: profile.usage_limit };
    }

    return { eligible: true, tier: profile.subscription_tier };
  } catch (err) {
    return { eligible: true };
  }
}

/**
 * Increments the current_usage counter for a user.
 */
export async function incrementUserUsage(githubOwner) {
  try {
    // We use a raw RPC or a select + update for simplicity here
    const { data: profile } = await supabase
      .from("profiles")
      .select("id, current_usage")
      .eq("github_username", githubOwner)
      .single();

    if (profile) {
      await supabase
        .from("profiles")
        .update({ current_usage: (profile.current_usage || 0) + 1 })
        .eq("id", profile.id);
    }
  } catch (err) {
    console.error("Usage increment failed:", err.message);
  }
}
