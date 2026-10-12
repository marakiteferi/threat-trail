import { useParams, Link } from 'react-router-dom'
import {
  Check,
  X,
  RefreshCw,
  ArrowLeft,
  Inbox,
  Award,
  CheckCircle2,
  AlertCircle,
  XCircle,
} from 'lucide-react'

function ScoreTier({ pct }) {
  if (pct === 100) return { label: 'Mastery — Perfect Score', icon: <Award size={14} />, cls: 'tier-perfect', color: '#f3c25b' }
  if (pct >= 80)   return { label: 'Proficient — Great Work',  icon: <CheckCircle2 size={14} />, cls: 'tier-great',   color: '#3fb950' }
  if (pct >= 60)   return { label: 'Passed — Standard Met',    icon: <CheckCircle2 size={14} />, cls: 'tier-pass',    color: '#58a6ff' }
  if (pct >= 40)   return { label: 'Review Advised',          icon: <AlertCircle size={14} />, cls: 'tier-warn',    color: '#d29922' }
  return               { label: 'Unsuccessful — Try Again',   icon: <XCircle size={14} />, cls: 'tier-fail',    color: '#f85149' }
}

export default function Report() {
  const { scenarioId } = useParams()
  const raw = sessionStorage.getItem(`report_${scenarioId}`)

  if (!raw) {
    return (
      <div className="rpt-no-data">
        <div className="rpt-no-data-icon">
          <Inbox size={42} />
        </div>
        <h2>No Report Data</h2>
        <p>Complete an investigation first to review your forensic analysis report.</p>
        <Link to="/" className="rpt-btn-back">
          <ArrowLeft size={14} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
          Return to Dashboard
        </Link>
      </div>
    )
  }

  const report   = JSON.parse(raw)
  const totalPts = report.total_points ?? (report.total_questions * 10)
  const earnedPts = report.points_earned ?? (report.correct_count * 10)
  const pct      = report.score_percent ?? Math.round((earnedPts / totalPts) * 100)
  const tier     = ScoreTier({ pct })

  // SVG ring
  const R = 52, C = 2 * Math.PI * R
  const dashOffset = C - (pct / 100) * C

  return (
    <div className="report-v2">

      {/* ── Score Hero ── */}
      <div className="rpt-hero">
        <div className="rpt-hero-bg" />
        <div className="rpt-hero-content">

          <div className="rpt-ring-wrap">
            <svg className="rpt-ring-svg" viewBox="0 0 120 120">
              <circle className="rpt-ring-track" cx="60" cy="60" r={R} />
              <circle
                className="rpt-ring-fill"
                cx="60" cy="60" r={R}
                style={{
                  stroke: tier.color,
                  strokeDasharray: C,
                  strokeDashoffset: dashOffset,
                }}
              />
            </svg>
            <div className="rpt-ring-center">
              <span className="rpt-pct" style={{ color: tier.color }}>{pct}%</span>
            </div>
          </div>

          <div className="rpt-hero-text">
            <h1 className="rpt-title">Investigation Report</h1>
            <div className={`rpt-tier ${tier.cls}`}>
              {tier.icon}
              <span style={{ marginLeft: 6 }}>{tier.label}</span>
            </div>
            <div className="rpt-pts-row">
              <span className="rpt-pts-earned" style={{ color: tier.color }}>{earnedPts}</span>
              <span className="rpt-pts-sep">/</span>
              <span className="rpt-pts-total">{totalPts} points</span>
            </div>
            <p className="rpt-summary">
              {report.correct_count} of {report.total_questions} questions answered correctly
            </p>
          </div>
        </div>
      </div>

      {/* ── Result Cards ── */}
      <div className="rpt-results-section">
        <h2 className="rpt-section-title">Answer Breakdown</h2>
        <div className="rpt-results-list">
          {report.results.map((r, i) => {
            const ptsAwarded = r.points_awarded ?? (r.is_correct ? (r.points_possible ?? 10) : 0)
            const ptsPossible = r.points_possible ?? 10
            return (
              <div key={r.question_id || i} className={`rpt-result-card ${r.is_correct ? 'rpt-correct' : 'rpt-incorrect'}`}>
                <div className="rpt-card-left">
                  <div className={`rpt-verdict-icon ${r.is_correct ? 'rpt-v-correct' : 'rpt-v-wrong'}`}>
                    {r.is_correct ? <Check size={14} /> : <X size={14} />}
                  </div>
                </div>
                <div className="rpt-card-body">
                  <div className="rpt-card-top-row">
                    <p className="rpt-q-text">{r.question_text}</p>
                    <span className={`rpt-pts-pill ${r.is_correct ? 'rpt-pill-correct' : 'rpt-pill-wrong'}`}>
                      {r.is_correct ? `+${ptsAwarded}` : `0`} / {ptsPossible} pts
                    </span>
                  </div>
                  <div className="rpt-answers">
                    <div className="rpt-answer-row">
                      <span className="rpt-answer-label">Your answer:</span>
                      <span className={`rpt-answer-val ${r.is_correct ? 'rpt-ans-correct' : 'rpt-ans-wrong'}`}>
                        {r.user_answer || <em style={{color:'var(--text-dim)'}}>blank</em>}
                      </span>
                    </div>
                    {!r.is_correct && (
                      <div className="rpt-answer-row">
                        <span className="rpt-answer-label">Correct answer:</span>
                        <span className="rpt-answer-val rpt-ans-correct">{r.correct_answer}</span>
                      </div>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* ── Actions ── */}
      <div className="rpt-actions">
        <Link to="/" className="rpt-btn-back">
          <ArrowLeft size={14} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
          Dashboard
        </Link>
        <Link to={`/investigate/${scenarioId}`} className="rpt-btn-retry">
          <RefreshCw size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
          Retry Investigation
        </Link>
      </div>
    </div>
  )
}
