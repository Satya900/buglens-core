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
}) {
  console.log(`📡 Connecting to Supabase to save PR #${prNumber} for ${repoFullName}...`)

  try {
    // 1. Find which user owns this repo (Must be exact string match)
    const { data: repo, error: repoError } = await supabase
      .from('repos')
      .select('user_id, id')
      .eq('repo_full_name', repoFullName)
      .single()

    if (repoError) {
      console.warn(`⏭ Repo ${repoFullName} not found in BugLens repos table. (Error: ${repoError.message})`)
      return
    }

    if (!repo) {
       console.warn(`⏭ Repo ${repoFullName} not registered. Skipping save.`)
       return
    }

    console.log(`👤 Found registered owner: ${repo.user_id}`)

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
