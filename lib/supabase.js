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

  const repo = repos && repos.length > 0 ? repos[0] : null;

  if (repoError) {
    console.warn(`Repo lookup error for ${repoFullName}: ${repoError.message}`);
  }

  if (repo) {
    return repo;
  }

  // Repo is not registered — reject. Users must connect repos via the BugLens dashboard first.
  console.error(`Rejected: Repo ${repoFullName} is not registered in the BugLens dashboard.`);
  return null;
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

/**
 * Returns true if this GitHub delivery has already been processed.
 * Prevents duplicate reviews when GitHub retries a webhook.
 */
export async function isDeliveryAlreadyProcessed(deliveryId) {
  if (!deliveryId) return false;
  try {
    const { data, error } = await supabase
      .from("reviews")
      .select("id")
      .eq("delivery_id", deliveryId)
      .limit(1);
    if (error) return false;
    return data && data.length > 0;
  } catch {
    return false;
  }
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
        delivery_id: deliveryId || null,
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
      shadowMode: repo.shadow_mode === true,
      reviewStrictness: repo.review_strictness || "balanced",
      userId: repo.user_id,
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

    if (error) {
      // PGRST116 = row not found (new user not yet in DB) — allow them through
      if (error.code === "PGRST116") return { eligible: true };
      // Any other error (network, DB outage) — fail closed to protect billing
      console.error(`Billing check failed for ${githubOwner}: ${error.message}`);
      return { eligible: false, tier: "UNKNOWN", error: true };
    }

    if (!profile) return { eligible: true }; // No profile yet — new user, allow

    if (profile.subscription_tier === "FREE" && profile.current_usage >= profile.usage_limit) {
      return { eligible: false, tier: "FREE", limit: profile.usage_limit };
    }

    return { eligible: true, tier: profile.subscription_tier };
  } catch (err) {
    // Unexpected crash — fail closed
    console.error(`Billing check crashed for ${githubOwner}:`, err.message);
    return { eligible: false, tier: "UNKNOWN", error: true };
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

/**
 * Fetches lessons learned from previous developer feedback for a specific repository.
 */
export async function getLessonsLearned({ repoFullName }) {
  try {
    const { data, error } = await supabase
      .from("lessons_learned")
      .select("content, rating")
      .eq("repo_full_name", repoFullName)
      .order("created_at", { ascending: false })
      .limit(5);

    if (error || !data || data.length === 0) {
      return [];
    }

    return data.map((l) => l.content);
  } catch (err) {
    return [];
  }
}

/**
 * Fetches the email address for a GitHub user from their profile.
 * Returns null if not found or on error — never throws.
 */
export async function getUserEmail(githubOwner) {
  try {
    const { data, error } = await supabase
      .from("profiles")
      .select("email")
      .eq("github_username", githubOwner)
      .single();
    if (error || !data) return null;
    return data.email || null;
  } catch {
    return null;
  }
}

/**
 * Saves a shadow review — runs analysis without posting to GitHub.
 * Used when shadow_mode is enabled on a repo.
 */
export async function saveShadowReview({
  repoFullName,
  prNumber,
  prTitle,
  prAuthor,
  prUrl,
  mergeDecision,
  riskSummary,
  filesReviewed,
  findings = [],
  repoProfile,
  deliveryId,
}) {
  try {
    const { error } = await supabase.from("shadow_reviews").insert({
      repo_full_name: repoFullName,
      pr_number: prNumber,
      pr_title: prTitle,
      pr_author: prAuthor,
      pr_url: prUrl,
      merge_decision: mergeDecision,
      risk_summary: riskSummary,
      files_reviewed: filesReviewed,
      findings_count: findings.length,
      findings_json: findings,
      repo_profile: repoProfile || null,
      delivery_id: deliveryId || null,
      created_at: new Date().toISOString(),
    });

    if (error) {
      console.error("Shadow review insert failed:", error.message);
    } else {
      console.log(`Shadow review saved for ${repoFullName} PR #${prNumber}.`);
    }
  } catch (err) {
    console.error("saveShadowReview crashed:", err.message);
  }
}
