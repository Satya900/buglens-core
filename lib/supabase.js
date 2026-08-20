import { createClient } from "@supabase/supabase-js";

// Lazily initialized so importing this module — or anything that transitively
// imports it, e.g. lib/repo-index.js's pure functions — doesn't require
// SUPABASE_URL/SUPABASE_SERVICE_ROLE_KEY to be set. Only actually calling one
// of this file's DB-touching functions does. Mirrors the lazy-client pattern
// already used in lib/ai-provider.js's getGeminiClient().
let _client = null;
function getClient() {
  if (!_client) {
    _client = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_ROLE_KEY);
  }
  return _client;
}
const supabase = new Proxy(
  {},
  {
    get(_target, prop) {
      const client = getClient();
      const value = client[prop];
      return typeof value === "function" ? value.bind(client) : value;
    },
  }
);

async function ensureRepoRecord({ repoFullName, githubOwner }) {
  const { data: repos, error: repoError } = await supabase
    .from("repos")
    .select("user_id, id, total_reviews, is_active, shadow_mode, review_strictness, auto_post_reviews")
    .eq("repo_full_name", repoFullName);

  if (repoError) {
    console.warn(`Repo lookup error for ${repoFullName}: ${repoError.message}`);
    return null;
  }

  if (!repos || repos.length === 0) {
    console.error(`Rejected: Repo ${repoFullName} is not registered in the BugLens dashboard.`);
    return null;
  }

  const active = repos.filter((r) => r.is_active !== false);
  const candidates = active.length > 0 ? active : repos;

  if (candidates.length === 1) {
    return candidates[0];
  }

  // Multiple owners for the same full name: prefer the profile that matches githubOwner.
  if (githubOwner) {
    const { data: profile } = await supabase
      .from("profiles")
      .select("id")
      .eq("github_username", githubOwner)
      .limit(1)
      .maybeSingle();

    if (profile?.id) {
      const owned = candidates.find((r) => r.user_id === profile.id);
      if (owned) return owned;
    }
  }

  console.error(
    `Rejected: Repo ${repoFullName} has ${candidates.length} matching rows and no unambiguous owner for ${githubOwner || "unknown"}.`
  );
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
    const { data: claimed, error: claimError } = await supabase
      .from("webhook_deliveries")
      .select("delivery_id")
      .eq("delivery_id", deliveryId)
      .limit(1);
    if (!claimError && claimed && claimed.length > 0) return true;

    const { data, error } = await supabase
      .from("reviews")
      .select("id")
      .eq("delivery_id", deliveryId)
      .limit(1);
    if (!error && data && data.length > 0) return true;

    // Shadow-mode reviews are saved to a separate table, so they need their
    // own dedup check — otherwise a redelivered webhook for a shadow-mode
    // repo would slip past this guard and produce a duplicate row.
    const { data: shadowData, error: shadowError } = await supabase
      .from("shadow_reviews")
      .select("id")
      .eq("delivery_id", deliveryId)
      .limit(1);
    if (shadowError) return false;
    return shadowData && shadowData.length > 0;
  } catch {
    return false;
  }
}

/**
 * Claims a delivery_id before expensive work starts.
 * Returns true if this process owns the delivery (insert succeeded).
 * Returns false if another worker already claimed it (or claim failed closed).
 */
export async function tryClaimDelivery(deliveryId) {
  if (!deliveryId) return true; // no id from GitHub → cannot claim; keep legacy behavior
  try {
    const { error } = await supabase.from("webhook_deliveries").insert({
      delivery_id: deliveryId,
    });
    if (!error) return true;
    // Unique violation = already claimed
    if (error.code === "23505") return false;
    console.error(`tryClaimDelivery failed for ${deliveryId}: ${error.message}`);
    return false;
  } catch (err) {
    console.error(`tryClaimDelivery crashed for ${deliveryId}:`, err.message);
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
      .select("id, subscription_tier, current_usage, usage_limit")
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

    return { eligible: true, tier: profile.subscription_tier, profileId: profile.id };
  } catch (err) {
    // Unexpected crash — fail closed
    console.error(`Billing check crashed for ${githubOwner}:`, err.message);
    return { eligible: false, tier: "UNKNOWN", error: true };
  }
}

/**
 * Increments the current_usage counter with a compare-and-swap so concurrent
 * PR webhooks cannot both pass a FREE-tier limit check.
 * Returns false if the row changed under us or the free limit is already hit.
 */
export async function incrementUserUsage(githubOwner) {
  try {
    const { data: profile } = await supabase
      .from("profiles")
      .select("id, current_usage, usage_limit, subscription_tier")
      .eq("github_username", githubOwner)
      .single();

    if (!profile) return false;

    const current = profile.current_usage || 0;
    if (profile.subscription_tier === "FREE" && current >= (profile.usage_limit ?? 0)) {
      return false;
    }

    const { data: updated, error } = await supabase
      .from("profiles")
      .update({ current_usage: current + 1 })
      .eq("id", profile.id)
      .eq("current_usage", current)
      .select("id");

    if (error) {
      console.error("Usage increment failed:", error.message);
      return false;
    }

    return Boolean(updated && updated.length > 0);
  } catch (err) {
    console.error("Usage increment failed:", err.message);
    return false;
  }
}

/**
 * Fetches lessons learned from previous developer feedback for a specific repository.
 * Always scoped to userId so two accounts on the same repo_full_name never share prompts.
 */
export async function getLessonsLearned({ repoFullName, userId }) {
  try {
    if (!userId) return [];

    const { data, error } = await supabase
      .from("lessons_learned")
      .select("content, rating")
      .eq("repo_full_name", repoFullName)
      .eq("user_id", userId)
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
/**
 * Returns { email, emailNotifications } for a GitHub user.
 * Used before sending review emails so we can respect the user's notification preference.
 */
export async function getUserEmailPrefs(githubOwner) {
  try {
    const { data, error } = await supabase
      .from("profiles")
      .select("email, email_notifications")
      .eq("github_username", githubOwner)
      .single();
    if (error || !data) return null;
    return {
      email: data.email || null,
      emailNotifications: data.email_notifications !== false, // default true
    };
  } catch {
    return null;
  }
}

/** @deprecated use getUserEmailPrefs */
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

/**
 * Attempts to acquire the indexing lock for a repo via an atomic
 * conditional update (Postgres serializes concurrent UPDATEs on the same
 * row, so this is a real compare-and-swap, not app-level locking).
 * Creates the meta row on first use if it doesn't exist yet.
 * Returns true if the caller now holds the lock.
 */
export async function tryAcquireIndexLock({ repoFullName, userId }) {
  try {
    await supabase
      .from("repo_index_meta")
      .upsert(
        { user_id: userId, repo_full_name: repoFullName },
        { onConflict: "user_id, repo_full_name", ignoreDuplicates: true }
      );

    const { data, error } = await supabase
      .from("repo_index_meta")
      .update({ status: "indexing" })
      .eq("repo_full_name", repoFullName)
      .eq("user_id", userId)
      .neq("status", "indexing")
      .select()
      .maybeSingle();

    return !error && !!data;
  } catch (err) {
    console.error("tryAcquireIndexLock crashed:", err.message);
    return false;
  }
}

export async function markIndexReady({ repoFullName, userId, sha, fileCount, capped }) {
  try {
    await supabase
      .from("repo_index_meta")
      .update({
        status: "ready",
        indexed_sha: sha,
        file_count: fileCount || 0,
        indexed_capped: !!capped,
        last_error: null,
        last_indexed_at: new Date().toISOString(),
      })
      .eq("repo_full_name", repoFullName)
      .eq("user_id", userId);
  } catch (err) {
    console.error("markIndexReady crashed:", err.message);
  }
}

export async function markIndexFailed({ repoFullName, userId, error }) {
  try {
    await supabase
      .from("repo_index_meta")
      .update({ status: "failed", last_error: String(error).slice(0, 500) })
      .eq("repo_full_name", repoFullName)
      .eq("user_id", userId);
  } catch (err) {
    console.error("markIndexFailed crashed:", err.message);
  }
}

export async function getRepoIndexMeta({ repoFullName, userId }) {
  try {
    const { data, error } = await supabase
      .from("repo_index_meta")
      .select("status, indexed_sha, file_count, indexed_capped")
      .eq("repo_full_name", repoFullName)
      .eq("user_id", userId)
      .maybeSingle();

    if (error || !data) return null;
    return data;
  } catch {
    return null;
  }
}

/**
 * Note: this client uses the Supabase service role key (see the top of this
 * file), which bypasses RLS entirely — the repo_index_* RLS policies protect
 * buglens-next's user-session-scoped dashboard queries, not this backend.
 * Every query here must filter by repo_full_name + user_id explicitly, the
 * same convention every other function in this file already follows.
 */
export async function getStoredIndexFiles({ repoFullName, userId }) {
  try {
    const { data, error } = await supabase
      .from("repo_index_files")
      .select("file_path, blob_sha, head_snippet, imports, imported_by")
      .eq("repo_full_name", repoFullName)
      .eq("user_id", userId);

    if (error || !data) return [];
    return data;
  } catch {
    return [];
  }
}

export async function upsertRepoIndexFiles({ repoFullName, userId, files }) {
  if (!files || files.length === 0) return;
  try {
    const rows = files.map((f) => ({
      user_id: userId,
      repo_full_name: repoFullName,
      file_path: f.file_path,
      blob_sha: f.blob_sha,
      head_snippet: f.head_snippet,
      imports: f.imports || [],
      imported_by: f.imported_by || [],
      indexed_sha: f.indexed_sha,
      updated_at: new Date().toISOString(),
    }));

    const { error } = await supabase
      .from("repo_index_files")
      .upsert(rows, { onConflict: "user_id, repo_full_name, file_path" });

    if (error) console.error("upsertRepoIndexFiles failed:", error.message);
  } catch (err) {
    console.error("upsertRepoIndexFiles crashed:", err.message);
  }
}

export async function pruneRepoIndexFiles({ repoFullName, userId, filePaths }) {
  if (!filePaths || filePaths.length === 0) return;
  try {
    const { error } = await supabase
      .from("repo_index_files")
      .delete()
      .eq("repo_full_name", repoFullName)
      .eq("user_id", userId)
      .in("file_path", filePaths);

    if (error) console.error("pruneRepoIndexFiles failed:", error.message);
  } catch (err) {
    console.error("pruneRepoIndexFiles crashed:", err.message);
  }
}
