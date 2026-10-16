import React, { useState, useEffect, useMemo } from 'react'
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
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)

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

  useEffect(() => {
    setCurrentPage(1)
  }, [selectedEventId, searchTerm])

  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / pageSize))
  const paginatedLogs = useMemo(() => {
    const start = (currentPage - 1) * pageSize
    return filteredLogs.slice(start, start + pageSize)
  }, [filteredLogs, currentPage, pageSize])

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
                      paginatedLogs.map((log) => {
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

              {filteredLogs.length > 0 && (
                <div className="inv-pagination-bar" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 12, padding: '8px 14px', background: 'var(--surface)', border: '1px solid var(--border)', borderRadius: 8, fontSize: '0.82rem' }}>
                  <div>
                    Showing <strong>{(currentPage - 1) * pageSize + 1}</strong>–<strong>{Math.min(currentPage * pageSize, filteredLogs.length)}</strong> of <strong>{filteredLogs.length}</strong> matching events
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <label style={{ color: 'var(--text-dim)' }}>
                      Rows:
                      <select
                        value={pageSize}
                        onChange={(e) => { setPageSize(Number(e.target.value)); setCurrentPage(1); }}
                        style={{ marginLeft: 6, background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 6px' }}
                      >
                        <option value={50}>50</option>
                        <option value={100}>100</option>
                        <option value={250}>250</option>
                      </select>
                    </label>
                    <button
                      type="button"
                      className="btn-sm btn-secondary"
                      disabled={currentPage <= 1}
                      onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                    >
                      ← Prev
                    </button>
                    <span>Page {currentPage} / {totalPages}</span>
                    <button
                      type="button"
                      className="btn-sm btn-secondary"
                      disabled={currentPage >= totalPages}
                      onClick={() => setCurrentPage((p) => Math.min(totalPages, p + 1))}
                    >
                      Next →
                    </button>
                  </div>
                </div>
              )}
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