import { createClient } from '@supabase/supabase-js'

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY // service role bypasses RLS for the engine
)

export async function saveReview({
  repoFullName,
  prNumber,
  prTitle,
  prAuthor,
  prUrl,
  mergeDecision,
  riskSummary,
  filesReviewed,
  findings,
  registrationOnly = false // 🤝 Handshake for onboarding
}) {
  console.log(`📡 Connecting to Supabase to save PR #${prNumber} for ${repoFullName}...`)

  try {
    // 1. Find which user owns this repo (Must be exact string match)
    const { data: repos, error: repoError } = await supabase
      .from('repos')
      .select('user_id, id')
      .eq('repo_full_name', repoFullName)

    let repo = repos && repos.length > 0 ? repos[0] : null;

    if (repoError) {
      console.warn(`⚠️ Repo lookup error for ${repoFullName}: ${repoError.message}`)
    }

    if (!repo) {
       console.log(`📡 Repo ${repoFullName} not found. Auto-registering under default user...`)
       const DEFAULT_USER_ID = "809138e0-d594-41b8-9156-72528b22ba14"; // Satya900's Account ID
       
       const { data: newRepo, error: createRepoError } = await supabase
         .from('repos')
         .insert({
           user_id: DEFAULT_USER_ID,
           repo_full_name: repoFullName,
           is_active: true, // 🚀 Mark as active immediately
           created_at: new Date().toISOString()
         })
         .select()
         .single()

       if (createRepoError) {
         console.error(`❌ Auto-onboarding failed for ${repoFullName}:`, createRepoError.message)
         return
       }
       repo = newRepo;
    }

    console.log(`👤 Assigned owner: ${repo.user_id}`)

    // 🚀 Handshake: Only register, don't save review
    if (registrationOnly) {
       return repo;
    }

    // 2. Insert review row
    const { data: review, error: reviewError } = await supabase
      .from('reviews')
      .insert({
        user_id: repo.user_id, // This should now be a valid UUID from the repos table
        repo_full_name: repoFullName,
        pr_number: prNumber,
        pr_title: prTitle,
        pr_author: prAuthor,
        pr_url: prUrl,
        merge_decision: mergeDecision,
        risk_summary: riskSummary,
        files_reviewed: filesReviewed,
        findings_count: findings.length,
        created_at: new Date().toISOString()
      })
      .select()
      .single()

    if (reviewError) {
      console.error('❌ saveReview Error (inserting review):', reviewError.message)
      return
    }

    console.log(`📄 Review Row Created! ID: ${review.id}`)

    // 3. Insert all findings
    if (findings.length > 0) {
      console.log(`⚡ Storing ${findings.length} AI findings...`)
      const { error: findingsError } = await supabase.from('findings').insert(
        findings.map((f) => ({
          review_id: review.id,
          file_path: f.file,
          line_number: f.line || 1,
          severity: f.severity || 'LOW',
          message: f.message,
          suggestion: f.suggestion,
        }))
      )
      if (findingsError) {
        console.error('❌ saveReview Error (inserting findings):', findingsError.message)
      }
    }

    // 4. Update repository stats
    const { error: updateError } = await supabase
      .from('repos')
      .update({
        last_review_at: new Date().toISOString(),
      })
      .eq('repo_full_name', repoFullName)

    if (updateError) {
        console.warn(`⚠️ Failed to update repo stats: ${updateError.message}`)
    }

    console.log(`✅ Review for PR #${prNumber} successfully synced to Dashboard!`)
    return review
  } catch (err) {
    console.error('❌ saveReview (Unexpected Exception):', err.message)
  }
}
