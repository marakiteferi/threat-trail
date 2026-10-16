import { useLocation, useParams, Link } from 'react-router-dom'

export default function Report() {
  const { scenarioId } = useParams()
  const location = useLocation()

  const stored = sessionStorage.getItem(`report_${scenarioId}`)
  const report = location.state?.report || (stored ? JSON.parse(stored) : null)

  if (!report) {
    return (
      <div className="report-v2">
        <div className="rpt-no-data">
          <div className="rpt-no-data-icon">📋</div>
          <h2>No Investigation Report Found</h2>
          <p>Complete and submit the scenario investigation to view your graded debrief.</p>
          <Link to={`/investigate/${scenarioId}`} className="btn btn-primary">
            Go to Investigation →
          </Link>
        </div>
      </div>
    )
  }

  const pct = report.score_percent ?? 0
  const radius = 50
  const circumference = 2 * Math.PI * radius
  const strokeDashoffset = circumference - (pct / 100) * circumference

  let tierLabel = 'Needs Review'
  let tierClass = 'tier-fail'
  let ringColor = '#ef4444'

  if (pct === 100) {
    tierLabel = '🏆 Senior SOC Analyst — Perfect Triage'
    tierClass = 'tier-perfect'
    ringColor = '#f3c25b'
  } else if (pct >= 80) {
    tierLabel = '✅ Tier-2 Incident Responder'
    tierClass = 'tier-great'
    ringColor = '#22c55e'
  } else if (pct >= 60) {
    tierLabel = '🛡️ Junior Analyst — Passing Grade'
    tierClass = 'tier-pass'
    ringColor = '#3b82f6'
  } else if (pct >= 40) {
    tierLabel = '⚠️ Partial Triage — Key IOCs Missed'
    tierClass = 'tier-warn'
    ringColor = '#f59e0b'
  }

  const pinnedIds = report.pinned_log_ids || []
  const keyEvidenceIds = report.key_evidence_log_ids || []
  const matchedPins = pinnedIds.filter((id) => keyEvidenceIds.includes(id))

  return (
    <div className="report-v2">
      <div className="rpt-hero">
        <div className="rpt-hero-bg" />
        <div className="rpt-hero-content">
          <div className="rpt-ring-wrap">
            <svg className="rpt-ring-svg" viewBox="0 0 120 120">
              <circle className="rpt-ring-track" cx="60" cy="60" r={radius} />
              <circle
                className="rpt-ring-fill"
                cx="60"
                cy="60"
                r={radius}
                stroke={ringColor}
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
              />
            </svg>
            <div className="rpt-ring-center">
              <span className="rpt-pct" style={{ color: ringColor }}>
                {pct}%
              </span>
            </div>
          </div>

          <div className="rpt-hero-text">
            <h2 className="rpt-title">Incident Debrief & Evaluation</h2>
            <div className={`rpt-tier ${tierClass}`}>{tierLabel}</div>
            <div className="rpt-pts-row">
              <span className="rpt-pts-earned">{report.points_earned}</span>
              <span className="rpt-pts-sep">/</span>
              <span className="rpt-pts-total">{report.total_points} points earned</span>
            </div>
            <p className="rpt-summary">
              You answered <strong>{report.correct_count}</strong> of{' '}
              <strong>{report.total_questions}</strong> investigation questions correctly
              {keyEvidenceIds.length > 0 && (
                <>
                  {' '}and pinned <strong>{matchedPins.length}/{keyEvidenceIds.length}</strong> key evidence logs.
                </>
              )}
            </p>
          </div>
        </div>
      </div>

      <div className="rpt-results-section">
        <h3 className="rpt-section-title">Question-by-Question Debrief</h3>
        <div className="rpt-results-list">
          {report.results.map((r) => (
            <div
              key={r.question_id}
              className={`rpt-result-card ${r.is_correct ? 'rpt-correct' : 'rpt-incorrect'}`}
            >
              <div className="rpt-card-left">
                <div className={`rpt-verdict-icon ${r.is_correct ? 'rpt-v-correct' : 'rpt-v-wrong'}`}>
                  {r.is_correct ? '✓' : '✗'}
                </div>
              </div>
              <div className="rpt-card-body">
                <div className="rpt-card-top-row">
                  <span className="rpt-q-text">{r.question_text}</span>
                  <span className={`rpt-pts-pill ${r.is_correct ? 'rpt-pill-correct' : 'rpt-pill-wrong'}`}>
                    {r.points_awarded} / {r.points_possible} pts
                  </span>
                </div>

                <div className="rpt-answers">
                  <div className="rpt-answer-row">
                    <span className="rpt-answer-label">Your Answer:</span>
                    <span className={`rpt-answer-val ${r.is_correct ? 'rpt-ans-correct' : 'rpt-ans-wrong'}`}>
                      {r.user_answer || '(blank)'}
                    </span>
                  </div>
                  {!r.is_correct && (
                    <div className="rpt-answer-row">
                      <span className="rpt-answer-label">Expected IOC:</span>
                      <span className="rpt-answer-val rpt-ans-correct">{r.correct_answer}</span>
                    </div>
                  )}
                  {r.explanation && (
                    <div className="rpt-explanation-box">
                      <strong>💡 Analyst Explanation:</strong> {r.explanation}
                    </div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="rpt-actions">
        <Link to="/" className="rpt-btn-back">
          ← Back to Scenarios
        </Link>
        <Link to={`/investigate/${scenarioId}`} className="rpt-btn-retry">
          ↻ Re-Investigate Scenario
        </Link>
      </div>
    </div>
  )
}
