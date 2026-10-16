#!/usr/bin/env python3
"""
apply_phase2_frontend_and_mordor.py
Run from the ThreatTrail project root:
    python apply_phase2_frontend_and_mordor.py
    python seed_mordor_scenarios.py

Upgrades:
1. threattrail-frontend/src/pages/Investigation.jsx (Sigma Rule Viewer, AD Context Lookup, Evidence Pinning & Timeline, Event ID Cheat Sheet, Event Filter Pills)
2. threattrail-frontend/src/pages/Report.jsx (Detailed Answer Explanations + Pinned Evidence Timeline Evaluation)
3. threattrail-frontend/src/pages/Admin.jsx (Atomic POST /admin/scenarios/full + Sigma Rule & Explanation fields)
4. threattrail-frontend/src/App.css (Styling for SOC drawers, badges, timeline, and cheat sheet)
5. seed_mordor_scenarios.py (Ingests the root Mordor .zip files into curated AD scenarios)
"""

from pathlib import Path

ROOT = Path(__file__).resolve().parent
FILES = {}

# ---------------------------------------------------------------------------
# 1. threattrail-frontend/src/pages/Investigation.jsx
# ---------------------------------------------------------------------------
FILES["threattrail-frontend/src/pages/Investigation.jsx"] = """import { useState, useEffect, useMemo } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import api from '../api'
import LogInspector from '../components/LogInspector'
import {
  ShieldAlert,
  Search,
  Pin,
  Code2,
  Network,
  BookOpen,
  Clock,
  CheckCircle2,
  ChevronDown,
  ChevronRight,
  Send,
  Filter
} from 'lucide-react'

const EVENT_CHEAT_SHEET = [
  { id: 4624, title: 'Successful Logon', desc: 'An account was successfully logged on. Check LogonType (3=Network, 10=RDP) & Source IP.' },
  { id: 4625, title: 'Failed Logon', desc: 'Failed authentication attempt. SubStatus 0xC000006A = Bad Password, 0xC0000064 = Unknown User.' },
  { id: 4769, title: 'Kerberos Service Ticket (TGS)', desc: 'Inspect TicketEncryptionType: 0x17 (RC4) often indicates Kerberoasting; 0x12 is AES256.' },
  { id: 4662, title: 'Directory Service Access', desc: 'Operation performed on an AD object. Replication GUIDs (1131f6aa...) indicate DCSync.' },
  { id: 4688, title: 'Process Creation', desc: 'A new process was spawned. Inspect NewProcessName and CommandLine.' },
  { id: 4672, title: 'Special Privileges Assigned', desc: 'Admin-equivalent privileges (SeDebugPrivilege, SeBackupPrivilege) assigned to logon.' },
  { id: 7045, title: 'Service Installed', desc: 'New Windows service registered (commonly used by PsExec / SMBExec).' },
  { id: 1, title: 'Sysmon: Process Create', desc: 'Detailed process creation with hashes, ParentImage, and CommandLine.' },
  { id: 10, title: 'Sysmon: ProcessAccess', desc: 'Process opened another process (e.g., Mimikatz accessing lsass.exe).' },
]

export default function Investigation() {
  const { scenarioId } = useParams()
  const navigate = useNavigate()

  const [scenario, setScenario] = useState(null)
  const [alert, setAlert] = useState(null)
  const [logs, setLogs] = useState([])
  const [questions, setQuestions] = useState([])
  const [answers, setAnswers] = useState({})
  const [pinnedLogIds, setPinnedLogIds] = useState([])

  // UI Toggles & Filters
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedEventId, setSelectedEventId] = useState('ALL')
  const [activeLeftTab, setActiveLeftTab] = useState('logs') // 'logs' | 'timeline' | 'ad_context' | 'cheatsheet'
  const [showSigmaModal, setShowSigmaModal] = useState(false)
  const [expandedLogId, setExpandedLogId] = useState(null)

  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    let isMounted = true
    setLoading(true)
    setError('')

    Promise.all([
      api.get(`/scenarios/${scenarioId}`).catch(() => ({ data: null })),
      api.get(`/scenarios/${scenarioId}/alert`).catch(() => ({ data: null })),
      api.get(`/scenarios/${scenarioId}/logs`),
      api.get(`/scenarios/${scenarioId}/questions`),
    ])
      .then(([scRes, alertRes, logsRes, qRes]) => {
        if (!isMounted) return
        setScenario(scRes.data)
        setAlert(alertRes.data)
        setLogs(logsRes.data || [])
        setQuestions(qRes.data || [])
      })
      .catch((err) => {
        if (!isMounted) return
        setError(err.response?.data?.detail || 'Failed to load investigation workspace.')
      })
      .finally(() => {
        if (isMounted) setLoading(false)
      })

    return () => {
      isMounted = false
    }
  }, [scenarioId])

  // Distinct Event IDs for quick filter chips
  const eventIdCounts = useMemo(() => {
    const counts = {}
    for (const log of logs) {
      counts[log.event_id] = (counts[log.event_id] || 0) + 1
    }
    return counts
  }, [logs])

  // Filtered logs
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      if (selectedEventId !== 'ALL' && String(log.event_id) !== String(selectedEventId)) {
        return false
      }
      if (!searchTerm.trim()) return true
      const term = searchTerm.toLowerCase()
      const matchEvent = String(log.event_id).includes(term)
      const matchIp = (log.source_ip || '').toLowerCase().includes(term)
      const matchUser = (log.username || '').toLowerCase().includes(term)
      const matchHost = (log.target_host || '').toLowerCase().includes(term)
      const matchRaw = JSON.stringify(log.raw_event_data || {}).toLowerCase().includes(term)
      return matchEvent || matchIp || matchUser || matchHost || matchRaw
    })
  }, [logs, selectedEventId, searchTerm])

  // Pinned logs sorted chronologically
  const pinnedLogs = useMemo(() => {
    return logs.filter((l) => pinnedLogIds.includes(l.id))
  }, [logs, pinnedLogIds])

  const togglePinLog = (e, logId) => {
    e.stopPropagation()
    setPinnedLogIds((prev) =>
      prev.includes(logId) ? prev.filter((id) => id !== logId) : [...prev, logId]
    )
  }

  const handleAnswerChange = (qId, val) => {
    setAnswers((prev) => ({ ...prev, [qId]: val }))
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    try {
      const payload = {
        answers: questions.map((q) => ({
          question_id: q.id,
          answer: answers[q.id] || '',
        })),
        pinned_log_ids: pinnedLogIds,
      }
      const res = await api.post(`/scenarios/${scenarioId}/submit`, payload)
      sessionStorage.setItem(`report_${scenarioId}`, JSON.stringify(res.data))
      navigate(`/report/${scenarioId}`, { state: { report: res.data } })
    } catch (err) {
      window.alert(err.response?.data?.detail || 'Submission failed')
    } finally {
      setSubmitting(false)
    }
  }

  if (loading) {
    return (
      <div className="db-loading">
        <div className="db-loading-spinner" />
        <span>Initializing SOC Investigation Workbench...</span>
      </div>
    )
  }

  if (error) {
    return (
      <div className="inv-error">
        <h3>⚠️ Workspace Error</h3>
        <p>{error}</p>
        <Link to="/" className="btn btn-primary" style={{ marginTop: 16 }}>
          ← Return to Dashboard
        </Link>
      </div>
    )
  }

  const answeredCount = questions.filter((q) => (answers[q.id] || '').trim().length > 0).length
  const progressPct = questions.length > 0 ? Math.round((answeredCount / questions.length) * 100) : 0
  const totalScenarioPoints = questions.reduce((acc, q) => acc + (q.points || 10), 0)

  const sevColor =
    alert?.severity === 'Critical'
      ? '#a855f7'
      : alert?.severity === 'High'
      ? '#ef4444'
      : alert?.severity === 'Medium'
      ? '#f59e0b'
      : '#22c55e'

  return (
    <div className="investigation-v2">
      {/* Top Alert Banner */}
      {alert && (
        <div
          className="inv-alert-banner"
          style={{
            background: `${sevColor}12`,
            borderColor: `${sevColor}55`,
          }}
        >
          <div className="inv-alert-left">
            <span className="inv-sev-pill" style={{ background: sevColor }}>
              {alert.severity}
            </span>
            <div className="inv-alert-body">
              <span className="inv-alert-label">
                TRIGGERED SIEM ALERT {scenario?.mitre_technique ? `• MITRE ${scenario.mitre_technique}` : ''}
              </span>
              <span className="inv-alert-title">{alert.title}</span>
            </div>
          </div>

          <div className="inv-alert-right">
            {alert.sigma_rule && (
              <button
                type="button"
                className={`soc-tool-btn ${showSigmaModal ? 'active' : ''}`}
                onClick={() => setShowSigmaModal(!showSigmaModal)}
              >
                <Code2 size={15} />
                <span>{showSigmaModal ? 'Hide Detection Logic' : 'View Sigma Rule'}</span>
              </button>
            )}
            <span className="inv-log-count">{logs.length} Events Captured</span>
            <Link to="/" className="inv-back-link">
              ← Exit Incident
            </Link>
          </div>
        </div>
      )}

      {/* Collapsible Sigma Detection Rule Drawer */}
      {showSigmaModal && alert?.sigma_rule && (
        <div className="sigma-rule-drawer">
          <div className="sigma-drawer-header">
            <div>
              <strong>⚡ Triggered Sigma Detection Rule (Static SIEM Logic)</strong>
              <p>Analyze the detection logic below to understand why this alert triggered and which Event IDs/fields to pivot on.</p>
            </div>
            <button type="button" className="btn-sm btn-secondary" onClick={() => setShowSigmaModal(false)}>
              Close
            </button>
          </div>
          <pre className="sigma-code-block">{alert.sigma_rule}</pre>
        </div>
      )}

      <div className="investigation-layout">
        {/* LEFT PANEL: Logs, Attack Timeline, AD Context, Cheat Sheet */}
        <div className="log-panel">
          {/* Workbench Navigation Bar */}
          <div className="soc-workbench-tabs">
            <button
              type="button"
              className={`soc-tab-btn ${activeLeftTab === 'logs' ? 'active' : ''}`}
              onClick={() => setActiveLeftTab('logs')}
            >
              <Filter size={15} />
              <span>Event Logs ({filteredLogs.length})</span>
            </button>

            <button
              type="button"
              className={`soc-tab-btn ${activeLeftTab === 'timeline' ? 'active' : ''}`}
              onClick={() => setActiveLeftTab('timeline')}
            >
              <Clock size={15} />
              <span>Pinned Timeline ({pinnedLogIds.length})</span>
            </button>

            {scenario?.ad_context && Object.keys(scenario.ad_context).length > 0 && (
              <button
                type="button"
                className={`soc-tab-btn ${activeLeftTab === 'ad_context' ? 'active' : ''}`}
                onClick={() => setActiveLeftTab('ad_context')}
              >
                <Network size={15} />
                <span>AD Environment Context</span>
              </button>
            )}

            <button
              type="button"
              className={`soc-tab-btn ${activeLeftTab === 'cheatsheet' ? 'active' : ''}`}
              onClick={() => setActiveLeftTab('cheatsheet')}
            >
              <BookOpen size={15} />
              <span>AD Event Cheat Sheet</span>
            </button>
          </div>

          {/* TAB 1: LOG VIEWER */}
          {activeLeftTab === 'logs' && (
            <>
              <div className="inv-panel-header">
                <div className="event-filter-chips">
                  <button
                    type="button"
                    className={`event-chip ${selectedEventId === 'ALL' ? 'active' : ''}`}
                    onClick={() => setSelectedEventId('ALL')}
                  >
                    All ({logs.length})
                  </button>
                  {Object.entries(eventIdCounts).map(([evId, cnt]) => (
                    <button
                      key={evId}
                      type="button"
                      className={`event-chip ${String(selectedEventId) === String(evId) ? 'active' : ''}`}
                      onClick={() => setSelectedEventId(evId)}
                    >
                      Event {evId} ({cnt})
                    </button>
                  ))}
                </div>

                <div className="inv-search-wrap">
                  <Search size={14} className="inv-search-icon" />
                  <input
                    type="text"
                    placeholder="Filter IP, user, host, or raw payload..."
                    value={searchTerm}
                    onChange={(e) => setSearchTerm(e.target.value)}
                    className="inv-search-input"
                  />
                  {searchTerm && (
                    <button
                      type="button"
                      className="inv-search-clear"
                      onClick={() => setSearchTerm('')}
                    >
                      ×
                    </button>
                  )}
                </div>
              </div>

              <div className="log-table-wrapper">
                <table className="log-table">
                  <thead>
                    <tr>
                      <th style={{ width: '42px' }}>Pin</th>
                      <th style={{ width: '130px' }}>Timestamp</th>
                      <th style={{ width: '95px' }}>Event ID</th>
                      <th style={{ width: '130px' }}>Source IP</th>
                      <th style={{ width: '150px' }}>Account / User</th>
                      <th>Target Host</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredLogs.length === 0 ? (
                      <tr>
                        <td colSpan="6" className="empty">
                          No logs match your active filter criteria.
                        </td>
                      </tr>
                    ) : (
                      filteredLogs.map((log) => {
                        const isExpanded = expandedLogId === log.id
                        const isPinned = pinnedLogIds.includes(log.id)
                        const dt = new Date(log.timestamp)
                        const dateStr = dt.toLocaleDateString()
                        const timeStr = dt.toLocaleTimeString()

                        const rowClass =
                          log.event_id === 4624
                            ? 'success-event'
                            : log.event_id === 4625
                            ? 'failure-event'
                            : ''

                        return (
                          <React.Fragment key={log.id}>
                            <tr
                              className={`inv-log-row ${rowClass} ${isExpanded ? 'log-row-expanded' : ''} ${
                                isPinned ? 'log-row-pinned' : ''
                              }`}
                              onClick={() => setExpandedLogId(isExpanded ? null : log.id)}
                            >
                              <td>
                                <button
                                  type="button"
                                  className={`pin-evidence-btn ${isPinned ? 'pinned' : ''}`}
                                  title={isPinned ? 'Remove from Attack Timeline' : 'Pin log as key evidence'}
                                  onClick={(e) => togglePinLog(e, log.id)}
                                >
                                  <Pin size={13} />
                                </button>
                              </td>
                              <td>
                                <span className="inv-ts-date">{dateStr}</span>
                                <span className="inv-ts-time">{timeStr}</span>
                              </td>
                              <td>
                                <span
                                  className={`event-badge ${
                                    log.event_id === 4624
                                      ? 'event-success'
                                      : log.event_id === 4625
                                      ? 'event-failure'
                                      : ''
                                  }`}
                                >
                                  {log.event_id}
                                </span>
                              </td>
                              <td className="inv-ip">{log.source_ip || '—'}</td>
                              <td>{log.username || '—'}</td>
                              <td>{log.target_host || '—'}</td>
                            </tr>
                            {isExpanded && (
                              <tr className="log-detail-row">
                                <td colSpan="6">
                                  <LogInspector log={log} />
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        )
                      })
                    )}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {/* TAB 2: PINNED ATTACK TIMELINE */}
          {activeLeftTab === 'timeline' && (
            <div className="soc-context-card">
              <h4>📌 Reconstructed Attack Timeline ({pinnedLogs.length} Pinned Events)</h4>
              <p className="soc-context-sub">
                Pin key events from the Event Logs tab using the pin icon to reconstruct the chronological attack chain. Your pinned evidence is submitted with your investigation report.
              </p>

              {pinnedLogs.length === 0 ? (
                <div className="empty" style={{ padding: '32px' }}>
                  No logs pinned yet. Click the 📌 icon next to suspicious events in the Event Logs tab.
                </div>
              ) : (
                <div className="timeline-list">
                  {pinnedLogs.map((log, idx) => (
                    <div key={log.id} className="timeline-item">
                      <div className="timeline-step-badge">{idx + 1}</div>
                      <div className="timeline-item-body">
                        <div className="timeline-item-top">
                          <span className="event-badge">Event {log.event_id}</span>
                          <span className="inv-ip">{new Date(log.timestamp).toLocaleString()}</span>
                          <span>User: <strong>{log.username || '—'}</strong></span>
                          <span>Source IP: <strong>{log.source_ip || '—'}</strong></span>
                          <span>Host: <strong>{log.target_host || '—'}</strong></span>
                          <button
                            type="button"
                            className="btn-sm btn-secondary"
                            onClick={(e) => togglePinLog(e, log.id)}
                          >
                            Unpin
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* TAB 3: ACTIVE DIRECTORY ENVIRONMENT CONTEXT */}
          {activeLeftTab === 'ad_context' && scenario?.ad_context && (
            <div className="soc-context-card">
              <h4>🏢 Active Directory Topology & Asset Directory</h4>
              <p className="soc-context-sub">
                Use this environment snapshot to cross-reference domain controllers, privileged accounts, SPNs, and lockout policies during your investigation.
              </p>
              <pre className="sigma-code-block">
                {JSON.stringify(scenario.ad_context, null, 2)}
              </pre>
            </div>
          )}

          {/* TAB 4: WINDOWS AD CHEAT SHEET */}
          {activeLeftTab === 'cheatsheet' && (
            <div className="soc-context-card">
              <h4>📖 Windows Active Directory SOC Event Reference</h4>
              <div className="cheatsheet-grid">
                {EVENT_CHEAT_SHEET.map((item) => (
                  <div key={item.id} className="cheatsheet-item">
                    <div className="cheatsheet-id">Event {item.id}</div>
                    <div>
                      <strong>{item.title}</strong>
                      <p>{item.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* RIGHT PANEL: Investigation Questions & Case Submission */}
        <div className="questions-panel inv-qa-panel">
          <div className="inv-qa-header">
            <div className="inv-qa-title">
              <h3>Investigation Findings</h3>
              <span className="total-scenario-pts">{totalScenarioPoints} Pts Total</span>
            </div>
            <div className="inv-progress-wrap">
              <div className="inv-progress-bar">
                <div className="inv-progress-fill" style={{ width: `${progressPct}%` }} />
              </div>
              <span className="inv-progress-label">
                {answeredCount}/{questions.length} Answered • {pinnedLogIds.length} Pinned
              </span>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="inv-qa-form">
            {questions.map((q, idx) => {
              const val = answers[q.id] || ''
              const isFilled = val.trim().length > 0
              return (
                <div
                  key={q.id}
                  className={`question-block inv-question-block ${isFilled ? 'inv-q-answered' : ''}`}
                >
                  <div className="inv-q-label-row">
                    <span className="inv-q-num">{idx + 1}</span>
                    <label className="inv-q-text">{q.question_text}</label>
                    <span className="q-points-badge">{q.points || 10} pts</span>
                  </div>
                  <div className="inv-input-wrap">
                    <input
                      type="text"
                      className={`answer-input inv-answer-input ${isFilled ? 'inv-input-filled' : ''}`}
                      placeholder="Enter finding (e.g. IP, username, MITRE ID)..."
                      value={val}
                      onChange={(e) => handleAnswerChange(q.id, e.target.value)}
                      required
                    />
                    {isFilled && <span className="inv-check">✓</span>}
                  </div>
                </div>
              )
            })}

            <button type="submit" className="inv-submit-btn" disabled={submitting}>
              {submitting ? (
                <>
                  <span className="inv-spinner" />
                  <span>Grading Investigation...</span>
                </>
              ) : (
                <>
                  <Send size={15} />
                  <span>Submit Incident Report</span>
                </>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
"""

# Fix React import in Investigation.jsx
FILES["threattrail-frontend/src/pages/Investigation.jsx"] = (
    "import React, { useState, useEffect, useMemo } from 'react'\n"
    + "\n".join(FILES["threattrail-frontend/src/pages/Investigation.jsx"].splitlines()[1:])
)

# ---------------------------------------------------------------------------
# 2. threattrail-frontend/src/pages/Report.jsx
# ---------------------------------------------------------------------------
FILES["threattrail-frontend/src/pages/Report.jsx"] = """import { useLocation, useParams, Link } from 'react-router-dom'

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
"""

# ---------------------------------------------------------------------------
# 3. Append new SOC Workbench styles to App.css
# ---------------------------------------------------------------------------
CSS_ADDITIONS = """
/* ── Phase 2 SOC Workbench Additions ── */
.soc-tool-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: rgba(59, 130, 246, 0.14);
  border: 1px solid rgba(59, 130, 246, 0.4);
  color: #93c5fd;
  padding: 5px 12px;
  border-radius: 6px;
  font-size: 0.78rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
}
.soc-tool-btn:hover, .soc-tool-btn.active {
  background: var(--accent);
  color: #fff;
}
.sigma-rule-drawer {
  background: #0d131f;
  border: 1px solid rgba(59, 130, 246, 0.4);
  border-radius: 10px;
  padding: 16px 20px;
  margin-bottom: 20px;
}
.sigma-drawer-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 12px;
  gap: 12px;
}
.sigma-drawer-header p {
  font-size: 0.82rem;
  color: var(--text-dim);
  margin-top: 2px;
}
.sigma-code-block {
  background: #070a10;
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 12px 16px;
  font-family: 'JetBrains Mono', monospace;
  font-size: 0.8rem;
  color: #7ee787;
  overflow-x: auto;
  white-space: pre-wrap;
}
.soc-workbench-tabs {
  display: flex;
  gap: 8px;
  margin-bottom: 14px;
  border-bottom: 1px solid var(--border);
  padding-bottom: 10px;
  flex-wrap: wrap;
}
.soc-tab-btn {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--text-dim);
  padding: 7px 14px;
  border-radius: 7px;
  font-size: 0.82rem;
  font-weight: 600;
  cursor: pointer;
  transition: all 0.15s ease;
}
.soc-tab-btn:hover {
  color: var(--text);
  border-color: var(--border-light);
}
.soc-tab-btn.active {
  background: rgba(59, 130, 246, 0.15);
  border-color: var(--accent);
  color: #60a5fa;
}
.event-filter-chips {
  display: flex;
  gap: 6px;
  flex-wrap: wrap;
}
.event-chip {
  background: var(--surface);
  border: 1px solid var(--border);
  color: var(--text-dim);
  padding: 4px 10px;
  border-radius: 16px;
  font-size: 0.75rem;
  font-weight: 600;
  cursor: pointer;
}
.event-chip.active {
  background: var(--accent);
  color: #fff;
  border-color: var(--accent);
}
.pin-evidence-btn {
  background: transparent;
  border: 1px solid var(--border);
  color: var(--text-muted);
  border-radius: 5px;
  padding: 4px;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
  justify-content: center;
}
.pin-evidence-btn.pinned {
  background: rgba(245, 158, 11, 0.2);
  border-color: #f59e0b;
  color: #fbbf24;
}
.log-row-pinned {
  background: rgba(245, 158, 11, 0.06) !important;
}
.soc-context-card {
  background: var(--surface);
  border: 1px solid var(--border);
  border-radius: 10px;
  padding: 20px;
}
.soc-context-sub {
  font-size: 0.85rem;
  color: var(--text-dim);
  margin: 6px 0 16px;
}
.timeline-list {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.timeline-item {
  display: flex;
  align-items: center;
  gap: 12px;
  background: var(--bg);
  border: 1px solid var(--border);
  padding: 10px 14px;
  border-radius: 8px;
}
.timeline-step-badge {
  width: 24px;
  height: 24px;
  border-radius: 50%;
  background: var(--accent);
  color: #fff;
  font-size: 0.75rem;
  font-weight: 700;
  display: flex;
  align-items: center;
  justify-content: center;
}
.timeline-item-top {
  display: flex;
  align-items: center;
  gap: 14px;
  flex-wrap: wrap;
  font-size: 0.83rem;
}
.cheatsheet-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 12px;
  margin-top: 12px;
}
.cheatsheet-item {
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 8px;
  padding: 12px;
  display: flex;
  flex-direction: column;
  gap: 6px;
}
.cheatsheet-id {
  font-family: monospace;
  font-size: 0.78rem;
  font-weight: 700;
  color: #60a5fa;
}
.cheatsheet-item p {
  font-size: 0.8rem;
  color: var(--text-dim);
}
.rpt-explanation-box {
  margin-top: 8px;
  padding: 8px 12px;
  background: rgba(59, 130, 246, 0.08);
  border-left: 3px solid var(--accent);
  border-radius: 0 6px 6px 0;
  font-size: 0.82rem;
  color: var(--text);
}
"""

# ---------------------------------------------------------------------------
# 4. seed_mordor_scenarios.py (Ingests the root Mordor .zip files!)
# ---------------------------------------------------------------------------
FILES["seed_mordor_scenarios.py"] = """#!/usr/bin/env python3
\"\"\"
seed_mordor_scenarios.py
Automatically ingests the real-world Mordor / OTRF Active Directory attack datasets
in the project root into curated ThreatTrail scenarios!
\"\"\"

import io
import json
import zipfile
from pathlib import Path
from datetime import datetime
from database import SessionLocal
from models import Scenario, Alert, Log, Question, SeverityLevel
from main import extract_field_from_message

ROOT = Path(__file__).resolve().parent

MORDOR_SCENARIOS = [
    {
        "zip_name": "covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges.zip",
        "name": "Active Directory DCSync Attack (Covenant C2)",
        "mitre_technique": "T1003.006",
        "description": (
            "An attacker with Domain Admin-equivalent privileges used Covenant C2 to perform a "
            "DCSync attack via the MS-DRSR Directory Replication Service (DsGetNCChanges) protocol "
            "to replicate password hashes from the Domain Controller. Investigate Event ID 4662 and "
            "network logon events to identify the compromised account and replication abuse."
        ),
        "alert_title": "Critical: Directory Replication Service (DCSync) Abuse Detected (Event 4662)",
        "severity": SeverityLevel.CRITICAL,
        "sigma_rule": \"\"\"title: Mimikatz / Covenant DCSync Replication (Event 4662)
status: stable
logsource:
  product: windows
  service: security
detection:
  selection:
    EventID: 4662
    Properties|contains:
      - '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2'
      - '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'
      - '89e95b76-444d-4c62-991a-0facbeda640c'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003.006\"\"\",
        "ad_context": {
            "domain": "shire.com",
            "attack_type": "DCSync (MS-DRSR DsGetNCChanges)",
            "critical_guids": {
                "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
                "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
            },
        },
        "questions": [
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for DCSync?",
                "correct_answer": "T1003.006",
                "acceptable_answers": ["T1003"],
                "explanation": "DCSync is categorized under OS Credential Dumping: DCSync (T1003.006).",
                "points": 15,
            },
            {
                "question_text": "Which Windows Security Event ID logs directory service object access used to detect DCSync?",
                "correct_answer": "4662",
                "acceptable_answers": ["4662"],
                "explanation": "Event ID 4662 ('An operation was performed on an object') logs AD replication rights checks.",
                "points": 20,
            },
        ],
    },
    {
        "zip_name": "empire_mimikatz_logonpasswords.zip",
        "name": "Empire Mimikatz LSASS Credential Dumping",
        "mitre_technique": "T1003.001",
        "description": (
            "A threat actor operating PowerShell Empire executed Mimikatz (sekurlsa::logonpasswords) "
            "on an Active Directory workstation to dump credentials from LSASS process memory. "
            "Analyze the Windows and Sysmon events to trace the credential dump."
        ),
        "alert_title": "Critical: Suspicious Process Access to LSASS Memory (Mimikatz)",
        "severity": SeverityLevel.CRITICAL,
        "sigma_rule": \"\"\"title: LSASS Memory Dump via Mimikatz (Sysmon Event 10)
status: stable
logsource:
  product: windows
  category: process_access
detection:
  selection:
    EventID: 10
    TargetImage|endswith: '\\\\lsass.exe'
    GrantedAccess|contains:
      - '0x1010'
      - '0x1410'
      - '0x1438'
  condition: selection
level: critical
tags:
  - attack.credential_access
  - attack.t1003.001\"\"\",
        "ad_context": {
            "target_process": "C:\\\\Windows\\\\System32\\\\lsass.exe",
            "tool": "PowerShell Empire / Invoke-Mimikatz",
        },
        "questions": [
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for dumping LSASS memory?",
                "correct_answer": "T1003.001",
                "acceptable_answers": ["T1003"],
                "explanation": "T1003.001 corresponds to OS Credential Dumping: LSASS Memory.",
                "points": 15,
            },
            {
                "question_text": "Which Windows system process is targeted by sekurlsa::logonpasswords?",
                "correct_answer": "lsass.exe",
                "acceptable_answers": ["lsass", "c:\\\\windows\\\\system32\\\\lsass.exe"],
                "explanation": "Local Security Authority Subsystem Service (lsass.exe) stores active logon credentials in memory.",
                "points": 20,
            },
        ],
    },
    {
        "zip_name": "cmd_psexec_lsa_secrets_dump.zip",
        "name": "PsExec Lateral Movement & LSA Secrets Dump",
        "mitre_technique": "T1003.004",
        "description": (
            "An adversary used Sysinternals PsExec to execute commands as SYSTEM and dump "
            "LSA Secrets from the registry. Investigate service creation (Event 7045 / 4697), "
            "process execution, and named pipe activity."
        ),
        "alert_title": "High Severity: PsExec Service Installation & LSA Secrets Access",
        "severity": SeverityLevel.HIGH,
        "sigma_rule": \"\"\"title: PsExec Service Execution (PSEXESVC)
status: stable
logsource:
  product: windows
  service: system
detection:
  selection:
    EventID: 7045
    ServiceName: 'PSEXESVC'
  condition: selection
level: high
tags:
  - attack.execution
  - attack.t1569.002\"\"\",
        "ad_context": {
            "service_binary": "PSEXESVC.exe",
            "technique": "PsExec SYSTEM escalation + LSA Secrets Dump",
        },
        "questions": [
            {
                "question_text": "What is the default service name installed by Sysinternals PsExec on the target host?",
                "correct_answer": "PSEXESVC",
                "acceptable_answers": ["psexesvc.exe"],
                "explanation": "PsExec drops and registers the PSEXESVC service binary on the remote Windows host.",
                "points": 20,
            },
            {
                "question_text": "What is the MITRE ATT&CK sub-technique ID for LSA Secrets credential dumping?",
                "correct_answer": "T1003.004",
                "acceptable_answers": ["T1003", "T1569.002"],
                "explanation": "T1003.004 is OS Credential Dumping: LSA Secrets.",
                "points": 15,
            },
        ],
    },
]


def parse_mordor_zip(zip_path: Path, scenario_id: int, max_logs: int = 120):
    entries = []
    with zipfile.ZipFile(zip_path, "r") as zf:
        for info in zf.infolist():
            if info.filename.endswith(".json") or info.filename.endswith(".jsonl"):
                with zf.open(info) as f:
                    raw = f.read().decode("utf-8", errors="replace").strip()
                    lines = [l.strip() for l in raw.split("\\n") if l.strip()]
                    for line in lines[:max_logs]:
                        try:
                            data = json.loads(line)
                        except Exception:
                            continue

                        ts_str = (
                            data.get("@timestamp")
                            or data.get("TimeCreated")
                            or data.get("EventTime")
                            or data.get("UtcTime")
                        )
                        try:
                            clean_ts = str(ts_str).replace("Z", "+00:00")
                            ts = datetime.fromisoformat(clean_ts).replace(tzinfo=None)
                        except Exception:
                            ts = datetime.now()

                        ev_raw = data.get("EventID") or data.get("event_id") or 0
                        if isinstance(ev_raw, dict):
                            ev_raw = ev_raw.get("$numberInt") or 0
                        try:
                            event_id = int(ev_raw)
                        except Exception:
                            event_id = 0

                        msg = data.get("Message") or ""
                        source_ip = (
                            data.get("IpAddress")
                            or data.get("SourceAddress")
                            or data.get("SourceIp")
                            or extract_field_from_message(msg, r"Source Network Address:\\s*([^\\r\\n\\t]+)")
                        )
                        username = (
                            data.get("TargetUserName")
                            or data.get("SubjectUserName")
                            or data.get("AccountName")
                            or extract_field_from_message(msg, r"Account Name:\\s*([^\\r\\n\\t]+)")
                        )
                        target_host = (
                            data.get("Hostname")
                            or data.get("Computer")
                            or data.get("host")
                        )

                        entries.append(
                            Log(
                                scenario_id=scenario_id,
                                event_id=event_id,
                                timestamp=ts,
                                source_ip=source_ip,
                                username=username,
                                target_host=target_host,
                                is_key_evidence=(event_id in (4662, 10, 7045, 4624)),
                                raw_event_data=data,
                            )
                        )
                if entries:
                    break
    return entries


def main():
    db = SessionLocal()
    try:
        for item in MORDOR_SCENARIOS:
            zpath = ROOT / item["zip_name"]
            if not zpath.exists():
                print(f"[SKIP] {item['zip_name']} not found in root.")
                continue

            existing = db.query(Scenario).filter(Scenario.name == item["name"]).first()
            if existing:
                print(f"[SKIP] Scenario '{item['name']}' already exists.")
                continue

            sc = Scenario(
                name=item["name"],
                description=item["description"],
                mitre_technique=item["mitre_technique"],
                status="Published",
                ad_context=item["ad_context"],
            )
            db.add(sc)
            db.flush()

            db.add(
                Alert(
                    scenario_id=sc.id,
                    title=item["alert_title"],
                    severity=item["severity"],
                    sigma_rule=item["sigma_rule"],
                )
            )

            for q in item["questions"]:
                db.add(
                    Question(
                        scenario_id=sc.id,
                        question_text=q["question_text"],
                        correct_answer=q["correct_answer"],
                        acceptable_answers=q["acceptable_answers"],
                        explanation=q["explanation"],
                        points=q["points"],
                    )
                )

            logs = parse_mordor_zip(zpath, sc.id, max_logs=120)
            db.add_all(logs)
            db.commit()
            print(f"[+] Imported '{item['name']}' with {len(logs)} real Mordor events!")
    finally:
        db.close()


if __name__ == "__main__":
    main()
"""


def main():
    print("=== Applying ThreatTrail Phase 2 Frontend & Mordor Dataset Seeder ===")
    for rel_path, content in FILES.items():
        target = ROOT / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        print(f"  [UPDATED] {rel_path}")

    # Append new styles to App.css if not already present
    app_css = ROOT / "threattrail-frontend/src/App.css"
    if app_css.exists():
        existing_css = app_css.read_text(encoding="utf-8")
        if "Phase 2 SOC Workbench Additions" not in existing_css:
            app_css.write_text(existing_css + "\n" + CSS_ADDITIONS, encoding="utf-8")
            print("  [APPENDED] threattrail-frontend/src/App.css")

    print("\n=== Next Steps ===")
    print("1. Run Mordor dataset seeder:  python seed_mordor_scenarios.py")
    print("2. Start frontend dev server:  cd threattrail-frontend && npm run dev")


if __name__ == "__main__":
    main()