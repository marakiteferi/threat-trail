import React, { useState, useEffect, useMemo, useCallback } from 'react'
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
  Filter,
  Zap,
  X,
  Eye,
  EyeOff,
  Info,
  HelpCircle,
  AlertTriangle,
  Lock,
  Lightbulb,
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

/** Detect likely external / attacker IPs: any IP that doesn't match common internal RFC-1918 ranges */
function classifyIPs(logs) {
  const internal = /^(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|127\.)/
  const byIp = {}
  for (const log of logs) {
    const ip = log.source_ip
    if (!ip || internal.test(ip)) continue
    byIp[ip] = (byIp[ip] || 0) + 1
  }
  // Also detect IPs that appear in bursts of failures (even if internal)
  const failures = {}
  for (const log of logs) {
    if (!log.source_ip) continue
    if (log.event_id === 4625 || log.event_id === 4771) {
      failures[log.source_ip] = (failures[log.source_ip] || 0) + 1
    }
  }
  for (const [ip, cnt] of Object.entries(failures)) {
    if (cnt >= 5 && !byIp[ip]) byIp[ip] = cnt
  }
  return byIp // { ip: count }
}

export default function Investigation() {
  const { scenarioId } = useParams()
  const navigate = useNavigate()

  const [scenario, setScenario] = useState(null)
  const [alert, setAlert] = useState(null)
  const [logs, setLogs] = useState([])
  const [questions, setQuestions] = useState([])
  const [answers, setAnswers] = useState({})
  const [pinnedLogIds, setPinnedLogIds] = useState([])

  // ── UI Toggles & Filters ──────────────────────────────────────────────────
  const [searchTerm, setSearchTerm] = useState('')
  // Multi-select: array of event ID strings. Empty = ALL
  const [selectedEventIds, setSelectedEventIds] = useState([])
  // Attacker-IP quick filter (single selection)
  const [selectedAttackerIp, setSelectedAttackerIp] = useState('')
  // Key-evidence-only toggle
  const [keyEvidenceOnly, setKeyEvidenceOnly] = useState(false)
  // Time-range filter: indices into sorted log array
  const [timeRangeIdx, setTimeRangeIdx] = useState([0, 100]) // [startPct, endPct] as percentage 0–100

  const [activeLeftTab, setActiveLeftTab] = useState('logs')
  const [showSigmaModal, setShowSigmaModal] = useState(false)
  const [expandedLogId, setExpandedLogId] = useState(null)
  const [currentPage, setCurrentPage] = useState(1)
  const [pageSize, setPageSize] = useState(50)

  const [loading, setLoading] = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState('')

  // ── Verification, Trials, Guesses & Hints ──────────────────────────────────
  const [trialsCount, setTrialsCount] = useState({})
  const [questionGuesses, setQuestionGuesses] = useState({})
  const [unlockedFreeHints, setUnlockedFreeHints] = useState({})
  const [freeHintsUsed, setFreeHintsUsed] = useState([]) // [qId, ...] free hints used (0 pts penalty)
  const [unlockedPaidHints, setUnlockedPaidHints] = useState({})
  const [hintsUsed, setHintsUsed] = useState([]) // Paid forensic hints (-15 pts each)
  const [verifyingId, setVerifyingId] = useState(null)
  const [verifyStatus, setVerifyStatus] = useState({})

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

    return () => { isMounted = false }
  }, [scenarioId])

  // ── Derived analytics ─────────────────────────────────────────────────────

  // Distinct Event IDs + counts
  const eventIdCounts = useMemo(() => {
    const counts = {}
    for (const log of logs) {
      counts[log.event_id] = (counts[log.event_id] || 0) + 1
    }
    return counts
  }, [logs])

  // Key evidence logs
  const keyEvidenceLogs = useMemo(() => logs.filter(l => l.is_key_evidence), [logs])

  // Detected attacker / suspicious IPs
  const suspiciousIps = useMemo(() => classifyIPs(logs), [logs])
  const suspiciousIpList = useMemo(() => Object.entries(suspiciousIps).sort((a, b) => b[1] - a[1]), [suspiciousIps])

  // Sorted timestamps for time-range slider
  const sortedTimestamps = useMemo(() => {
    if (!logs.length) return []
    return logs.map(l => new Date(l.timestamp).getTime()).sort((a, b) => a - b)
  }, [logs])

  const minTs = sortedTimestamps[0] || 0
  const maxTs = sortedTimestamps[sortedTimestamps.length - 1] || 0

  // Convert percentage to actual timestamp
  const pctToTs = useCallback((pct) => {
    if (minTs === maxTs) return minTs
    return minTs + ((maxTs - minTs) * pct) / 100
  }, [minTs, maxTs])

  const filterStartTs = pctToTs(timeRangeIdx[0])
  const filterEndTs = pctToTs(timeRangeIdx[1])

  // Check if any filter is active (besides search)
  const anyFilterActive =
    selectedEventIds.length > 0 ||
    selectedAttackerIp !== '' ||
    keyEvidenceOnly ||
    timeRangeIdx[0] !== 0 ||
    timeRangeIdx[1] !== 100 ||
    searchTerm.trim() !== ''

  const clearAllFilters = () => {
    setSelectedEventIds([])
    setSelectedAttackerIp('')
    setKeyEvidenceOnly(false)
    setTimeRangeIdx([0, 100])
    setSearchTerm('')
  }

  // ── Filtered logs ─────────────────────────────────────────────────────────
  const filteredLogs = useMemo(() => {
    return logs.filter((log) => {
      // 1. Multi-select event ID filter
      if (selectedEventIds.length > 0 && !selectedEventIds.includes(String(log.event_id))) return false

      // 2. Attacker-IP quick filter
      if (selectedAttackerIp && log.source_ip !== selectedAttackerIp) return false

      // 3. Key-evidence-only
      if (keyEvidenceOnly && !log.is_key_evidence) return false

      // 4. Time-range
      const ts = new Date(log.timestamp).getTime()
      if (ts < filterStartTs || ts > filterEndTs) return false

      // 5. Free-text search: event_id, ip, user, host, full raw JSON
      if (searchTerm.trim()) {
        const term = searchTerm.toLowerCase()
        const matchEvent = String(log.event_id).includes(term)
        const matchIp = (log.source_ip || '').toLowerCase().includes(term)
        const matchUser = (log.username || '').toLowerCase().includes(term)
        const matchHost = (log.target_host || '').toLowerCase().includes(term)
        const matchRaw = JSON.stringify(log.raw_event_data || {}).toLowerCase().includes(term)
        if (!matchEvent && !matchIp && !matchUser && !matchHost && !matchRaw) return false
      }

      return true
    })
  }, [logs, selectedEventIds, selectedAttackerIp, keyEvidenceOnly, filterStartTs, filterEndTs, searchTerm])

  // Reset to page 1 whenever any filter changes
  useEffect(() => { setCurrentPage(1) }, [selectedEventIds, selectedAttackerIp, keyEvidenceOnly, timeRangeIdx, searchTerm])

  const totalPages = Math.max(1, Math.ceil(filteredLogs.length / pageSize))
  const paginatedLogs = useMemo(() => {
    const start = (currentPage - 1) * pageSize
    return filteredLogs.slice(start, start + pageSize)
  }, [filteredLogs, currentPage, pageSize])

  // ── Pinned logs ───────────────────────────────────────────────────────────
  const pinnedLogs = useMemo(() => logs.filter((l) => pinnedLogIds.includes(l.id)), [logs, pinnedLogIds])

  const togglePinLog = (e, logId) => {
    e.stopPropagation()
    setPinnedLogIds((prev) => prev.includes(logId) ? prev.filter((id) => id !== logId) : [...prev, logId])
  }

  // Toggle a single event ID in multi-select
  const toggleEventId = (evId) => {
    setSelectedEventIds(prev =>
      prev.includes(evId) ? prev.filter(id => id !== evId) : [...prev, evId]
    )
  }

  const handleAnswerChange = (qId, val) => {
    setAnswers((prev) => ({ ...prev, [qId]: val }))
  }

  const handleVerifyFinding = async (questionId) => {
    const answer = (answers[questionId] || '').trim()
    if (!answer) return

    setVerifyingId(questionId)
    try {
      const res = await api.post(`/scenarios/${scenarioId}/verify-finding`, {
        question_id: questionId,
        answer: answer,
      })
      const isCorrect = res.data.is_correct

      // Record guess in questionGuesses
      setQuestionGuesses(prev => ({
        ...prev,
        [questionId]: [...(prev[questionId] || []), answer]
      }))

      if (!isCorrect) {
        setTrialsCount(prev => ({
          ...prev,
          [questionId]: (prev[questionId] || 0) + 1
        }))
      }

      setVerifyStatus(prev => ({
        ...prev,
        [questionId]: {
          correct: isCorrect,
          message: res.data.message
        }
      }))
    } catch (err) {
      console.error('Failed to verify finding:', err)
    } finally {
      setVerifyingId(null)
    }
  }

  const handleUseFreeHint = async (questionId, qIndex) => {
    if (unlockedFreeHints[questionId]) return

    try {
      const res = await api.post(`/scenarios/${scenarioId}/questions/${questionId}/hint?is_free=true`)
      setUnlockedFreeHints(prev => ({
        ...prev,
        [questionId]: res.data.hint
      }))
      setFreeHintsUsed(prev => prev.includes(questionId) ? prev : [...prev, questionId])
    } catch (err) {
      window.alert('Failed to retrieve free hint: ' + (err.response?.data?.detail || err.message))
    }
  }

  const handleUnlockPaidHint = async (questionId) => {
    if (unlockedPaidHints[questionId]) return

    const confirmed = window.confirm(
      "⚠️ FORENSIC HINT DEDUCTION\n\nUnlocking this forensic hint will deduct 15 points from your scenario score.\n\nDo you want to unlock the hint?"
    )
    if (!confirmed) return

    try {
      const res = await api.post(`/scenarios/${scenarioId}/questions/${questionId}/hint?is_free=false`)
      setUnlockedPaidHints(prev => ({
        ...prev,
        [questionId]: res.data.hint
      }))
      setHintsUsed(prev => prev.includes(questionId) ? prev : [...prev, questionId])
    } catch (err) {
      window.alert('Failed to retrieve hint: ' + (err.response?.data?.detail || err.message))
    }
  }

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    try {
      const totalTrials = Object.values(trialsCount).reduce((a, b) => a + b, 0) + 1
      const payload = {
        answers: questions.map((q) => ({
          question_id: q.id,
          answer: answers[q.id] || '',
        })),
        pinned_log_ids: pinnedLogIds,
        hints_used: hintsUsed,
        free_hint_id: freeHintsUsed[0] || null,
        free_hints_used: freeHintsUsed,
        trials_count: totalTrials,
        user_guesses: questionGuesses,
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
      {/* ── Top Alert Banner ── */}
      {alert && (
        <div
          className="inv-alert-banner"
          style={{ background: `${sevColor}12`, borderColor: `${sevColor}55` }}
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
            <button
              type="button"
              className="inv-back-btn"
              onClick={() => navigate(-1)}
              title="Go back to previous page"
            >
              ← Back
            </button>
          </div>
        </div>
      )}

      {/* ── Sigma Rule Drawer ── */}
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
        {/* ── LEFT PANEL ── */}
        <div className="log-panel">
          {/* Workbench Navigation Tabs */}
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
                <span>AD Environment</span>
              </button>
            )}

            <button
              type="button"
              className={`soc-tab-btn ${activeLeftTab === 'cheatsheet' ? 'active' : ''}`}
              onClick={() => setActiveLeftTab('cheatsheet')}
            >
              <BookOpen size={15} />
              <span>Event Cheat Sheet</span>
            </button>
          </div>

          {/* ── TAB 1: LOG VIEWER ── */}
          {activeLeftTab === 'logs' && (
            <>
              {/* ─── Smart Filter Toolbar ─── */}
              <div className="smart-filter-toolbar">

                {/* Row 1: Event ID chips + Key Evidence toggle */}
                <div className="filter-row">
                  <div className="filter-label">
                    <Filter size={12} />
                    Event IDs
                  </div>
                  <div className="event-filter-chips">
                    <button
                      type="button"
                      className={`event-chip ${selectedEventIds.length === 0 ? 'active' : ''}`}
                      onClick={() => setSelectedEventIds([])}
                    >
                      All ({logs.length})
                    </button>
                    {Object.entries(eventIdCounts).map(([evId, cnt]) => (
                      <button
                        key={evId}
                        type="button"
                        className={`event-chip ${selectedEventIds.includes(evId) ? 'active' : ''}`}
                        onClick={() => toggleEventId(evId)}
                        title="Click to add/remove from filter. Multiple can be selected."
                      >
                        {evId} ({cnt})
                      </button>
                    ))}
                  </div>
                  <button
                    type="button"
                    className={`filter-toggle-btn ${keyEvidenceOnly ? 'active' : ''}`}
                    onClick={() => setKeyEvidenceOnly(v => !v)}
                    title="Show only logs marked as key evidence by the scenario author"
                  >
                    <Zap size={12} />
                    Key Evidence ({keyEvidenceLogs.length})
                  </button>
                </div>

                {/* Event ID Guide Callout */}
                <div className="event-id-hint-banner">
                  <Info size={13} className="event-hint-icon" />
                  <span>
                    <strong>Event ID Guide:</strong> Event IDs indicate action categories (e.g. <code>4625</code> = Failed Logon, <code>4624</code> = Successful Logon). Repeated Event IDs show repeated attempts or background events. Use <strong>Timestamp</strong>, <strong>Username</strong>, and <strong>Source IP</strong> to tell them apart.
                  </span>
                </div>

                {/* Row 2: Attacker IP quick-filter (only shown if suspicious IPs detected) */}
                {suspiciousIpList.length > 0 && (
                  <div className="filter-row">
                    <div className="filter-label" style={{ color: '#ef4444' }}>
                      <ShieldAlert size={12} />
                      Suspect IPs
                    </div>
                    <div className="event-filter-chips">
                      <button
                        type="button"
                        className={`event-chip attacker-chip ${selectedAttackerIp === '' ? 'active' : ''}`}
                        onClick={() => setSelectedAttackerIp('')}
                      >
                        All Sources
                      </button>
                      {suspiciousIpList.map(([ip, cnt]) => (
                        <button
                          key={ip}
                          type="button"
                          className={`event-chip attacker-chip ${selectedAttackerIp === ip ? 'active' : ''}`}
                          onClick={() => setSelectedAttackerIp(prev => prev === ip ? '' : ip)}
                          title={`${cnt} events from this IP — possible attacker source`}
                        >
                          🔴 {ip} ({cnt})
                        </button>
                      ))}
                    </div>
                  </div>
                )}

                {/* Row 3: Time range slider */}
                {sortedTimestamps.length > 1 && (
                  <div className="filter-row filter-row-time">
                    <div className="filter-label">
                      <Clock size={12} />
                      Time Range
                    </div>
                    <div className="time-range-wrap">
                      <span className="time-range-label">
                        {new Date(filterStartTs).toLocaleTimeString()}
                      </span>
                      <div className="dual-slider-wrap">
                        <input
                          type="range"
                          min={0}
                          max={100}
                          step={1}
                          value={timeRangeIdx[0]}
                          className="range-slider range-slider-start"
                          onChange={e => {
                            const v = Number(e.target.value)
                            setTimeRangeIdx(prev => [Math.min(v, prev[1] - 1), prev[1]])
                          }}
                        />
                        <input
                          type="range"
                          min={0}
                          max={100}
                          step={1}
                          value={timeRangeIdx[1]}
                          className="range-slider range-slider-end"
                          onChange={e => {
                            const v = Number(e.target.value)
                            setTimeRangeIdx(prev => [prev[0], Math.max(v, prev[0] + 1)])
                          }}
                        />
                      </div>
                      <span className="time-range-label">
                        {new Date(filterEndTs).toLocaleTimeString()}
                      </span>
                    </div>
                    {(timeRangeIdx[0] !== 0 || timeRangeIdx[1] !== 100) && (
                      <button
                        type="button"
                        className="filter-clear-mini"
                        onClick={() => setTimeRangeIdx([0, 100])}
                        title="Reset time range"
                      >
                        <X size={11} /> Reset
                      </button>
                    )}
                  </div>
                )}

                {/* Row 4: Free-text search + active filter summary + clear */}
                <div className="filter-row">
                  <div className="inv-search-wrap" style={{ flex: 1 }}>
                    <Search size={14} className="inv-search-icon" />
                    <input
                      type="text"
                      placeholder="Search IP, user, host, hex value, Event ID, or any raw field..."
                      value={searchTerm}
                      onChange={(e) => setSearchTerm(e.target.value)}
                      className="inv-search-input"
                    />
                    {searchTerm && (
                      <button type="button" className="inv-search-clear" onClick={() => setSearchTerm('')}>×</button>
                    )}
                  </div>
                  {anyFilterActive && (
                    <button type="button" className="filter-clear-all-btn" onClick={clearAllFilters}>
                      <X size={13} /> Clear All Filters
                    </button>
                  )}
                </div>

                {/* Active filter summary chips */}
                {(selectedEventIds.length > 0 || selectedAttackerIp || keyEvidenceOnly) && (
                  <div className="active-filter-pills">
                    {selectedEventIds.map(evId => (
                      <span key={evId} className="active-filter-pill">
                        Event {evId}
                        <button type="button" onClick={() => toggleEventId(evId)}><X size={10} /></button>
                      </span>
                    ))}
                    {selectedAttackerIp && (
                      <span className="active-filter-pill pill-attacker">
                        🔴 {selectedAttackerIp}
                        <button type="button" onClick={() => setSelectedAttackerIp('')}><X size={10} /></button>
                      </span>
                    )}
                    {keyEvidenceOnly && (
                      <span className="active-filter-pill pill-evidence">
                        ⚡ Key Evidence Only
                        <button type="button" onClick={() => setKeyEvidenceOnly(false)}><X size={10} /></button>
                      </span>
                    )}
                    <span className="active-filter-result">
                      → {filteredLogs.length} of {logs.length} events
                    </span>
                  </div>
                )}
              </div>

              {/* ─── Color Legend & Detection Hint Bar ─── */}
              <div className="log-color-legend">
                <div className="legend-label">
                  <Eye size={13} />
                  <span>Color Guide & Hints:</span>
                </div>
                <div className="legend-items">
                  <div
                    className={`legend-pill pill-red ${selectedEventIds.includes('4625') ? 'active' : ''}`}
                    onClick={() => toggleEventId('4625')}
                    title="Click to toggle Event 4625 (Failed Logon) filter"
                  >
                    <span className="legend-dot dot-red" />
                    <span className="legend-name">Red (4625/4771)</span>
                    <span className="legend-desc">Auth Failure (Spray/Brute Force)</span>
                  </div>

                  <div
                    className={`legend-pill pill-green ${selectedEventIds.includes('4624') ? 'active' : ''}`}
                    onClick={() => toggleEventId('4624')}
                    title="Click to toggle Event 4624 (Successful Logon) filter"
                  >
                    <span className="legend-dot dot-green" />
                    <span className="legend-name">Green (4624/4672)</span>
                    <span className="legend-desc">Success (Compromised Logon)</span>
                  </div>

                  <div
                    className={`legend-pill pill-orange ${selectedEventIds.includes('4769') ? 'active' : ''}`}
                    onClick={() => toggleEventId('4769')}
                    title="Click to toggle Event 4769 (Kerberos) filter"
                  >
                    <span className="legend-dot dot-orange" />
                    <span className="legend-name">Orange (4769/4768)</span>
                    <span className="legend-desc">Kerberos TGS / Kerberoasting</span>
                  </div>

                  <div
                    className={`legend-pill pill-purple ${selectedEventIds.includes('4662') ? 'active' : ''}`}
                    onClick={() => toggleEventId('4662')}
                    title="Click to toggle Event 4662 (DCSync) filter"
                  >
                    <span className="legend-dot dot-purple" />
                    <span className="legend-name">Purple (4662/7045)</span>
                    <span className="legend-desc">DCSync / Service Install</span>
                  </div>

                  <div
                    className={`legend-pill pill-cyan ${selectedEventIds.includes('4688') ? 'active' : ''}`}
                    onClick={() => toggleEventId('4688')}
                    title="Click to toggle Event 4688 (Process) filter"
                  >
                    <span className="legend-dot dot-cyan" />
                    <span className="legend-name">Cyan (4688/Sysmon)</span>
                    <span className="legend-desc">Process Execution</span>
                  </div>

                  <div
                    className={`legend-pill pill-gold ${keyEvidenceOnly ? 'active' : ''}`}
                    onClick={() => setKeyEvidenceOnly(v => !v)}
                    title="Click to toggle key evidence"
                  >
                    <span className="legend-badge-bolt">⚡</span>
                    <span className="legend-name">Gold Badge</span>
                    <span className="legend-desc">Key Evidence</span>
                  </div>

                  <div className="legend-pill pill-suspect-ip" title="IP generating abnormal authentication failures">
                    <span className="suspect-ip-dot" />
                    <span className="legend-name">Pulsing Dot</span>
                    <span className="legend-desc">Suspect IP</span>
                  </div>
                </div>
              </div>

              {/* ─── Log Table ─── */}
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
                          {anyFilterActive && (
                            <button type="button" className="btn-sm btn-secondary" style={{ marginLeft: 10 }} onClick={clearAllFilters}>
                              Clear Filters
                            </button>
                          )}
                        </td>
                      </tr>
                    ) : (
                      paginatedLogs.map((log) => {
                        const isExpanded = expandedLogId === log.id
                        const isPinned = pinnedLogIds.includes(log.id)
                        const isKeyEvidence = log.is_key_evidence
                        const isSuspectIp = suspiciousIps[log.source_ip] !== undefined
                        const dt = new Date(log.timestamp)
                        const dateStr = dt.toLocaleDateString()
                        const timeStr = dt.toLocaleTimeString()

                        const rowClass =
                          isKeyEvidence
                            ? 'key-evidence-row'
                            : log.event_id === 4625 || log.event_id === 4771
                            ? 'failure-event'
                            : log.event_id === 4624
                            ? 'success-event'
                            : log.event_id === 4769 || log.event_id === 4768
                            ? 'kerberos-event'
                            : log.event_id === 4662
                            ? 'privilege-event'
                            : ''

                        const getBadgeClass = (evId) => {
                          if (evId === 4624 || evId === 4672) return 'event-success'
                          if (evId === 4625 || evId === 4771) return 'event-failure'
                          if (evId === 4768 || evId === 4769) return 'event-kerberos'
                          if (evId === 4662 || evId === 7045) return 'event-privilege'
                          if (evId === 4688 || evId === 1 || evId === 3 || evId === 10) return 'event-process'
                          return ''
                        }

                        return (
                          <React.Fragment key={log.id}>
                            <tr
                              className={`inv-log-row ${rowClass} ${isExpanded ? 'log-row-expanded' : ''} ${isPinned ? 'log-row-pinned' : ''}`}
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
                                <span className={`event-badge ${getBadgeClass(log.event_id)}`}>
                                  {log.event_id}
                                </span>
                                {isKeyEvidence && (
                                  <span className="key-evidence-badge" title="Flagged as key evidence by scenario author">
                                    ⚡
                                  </span>
                                )}
                              </td>
                              <td className={`inv-ip ${isSuspectIp ? 'suspect-ip' : ''}`}>
                                {log.source_ip || '—'}
                                {isSuspectIp && <span className="suspect-ip-dot" title="Suspicious source IP" />}
                              </td>
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
                <div className="inv-pagination-bar">
                  <div>
                    Showing <strong>{(currentPage - 1) * pageSize + 1}</strong>–<strong>{Math.min(currentPage * pageSize, filteredLogs.length)}</strong> of <strong>{filteredLogs.length}</strong> events
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <label style={{ color: 'var(--text-dim)' }}>
                      Rows:
                      <select
                        value={pageSize}
                        onChange={(e) => { setPageSize(Number(e.target.value)); setCurrentPage(1) }}
                        style={{ marginLeft: 6, background: 'var(--bg)', color: 'var(--text)', border: '1px solid var(--border)', borderRadius: 4, padding: '2px 6px' }}
                      >
                        <option value={50}>50</option>
                        <option value={100}>100</option>
                        <option value={250}>250</option>
                        <option value={500}>500</option>
                      </select>
                    </label>
                    <button type="button" className="btn-sm btn-secondary" disabled={currentPage <= 1} onClick={() => setCurrentPage(p => Math.max(1, p - 1))}>
                      ← Prev
                    </button>
                    <span>Page {currentPage} / {totalPages}</span>
                    <button type="button" className="btn-sm btn-secondary" disabled={currentPage >= totalPages} onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}>
                      Next →
                    </button>
                  </div>
                </div>
              )}
            </>
          )}

          {/* ── TAB 2: PINNED ATTACK TIMELINE ── */}
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
                    <div key={log.id} className={`timeline-item ${log.is_key_evidence ? 'timeline-key-evidence' : ''}`}>
                      <div className="timeline-step-badge">{idx + 1}</div>
                      <div className="timeline-item-body">
                        <div className="timeline-item-top">
                          <span className="event-badge">Event {log.event_id}</span>
                          {log.is_key_evidence && <span className="key-evidence-badge">⚡ Key Evidence</span>}
                          <span className="inv-ip">{new Date(log.timestamp).toLocaleString()}</span>
                          <span>User: <strong>{log.username || '—'}</strong></span>
                          <span>Source IP: <strong>{log.source_ip || '—'}</strong></span>
                          <span>Host: <strong>{log.target_host || '—'}</strong></span>
                          <button type="button" className="btn-sm btn-secondary" onClick={(e) => togglePinLog(e, log.id)}>
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

          {/* ── TAB 3: AD CONTEXT ── */}
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

          {/* ── TAB 4: CHEAT SHEET ── */}
          {activeLeftTab === 'cheatsheet' && (
            <div className="soc-context-card">
              <h4>📖 Windows Active Directory SOC Event Reference</h4>
              <div className="cheatsheet-grid">
                {EVENT_CHEAT_SHEET.map((item) => (
                  <div
                    key={item.id}
                    className={`cheatsheet-item ${selectedEventIds.includes(String(item.id)) ? 'cheatsheet-item-active' : ''}`}
                    onClick={() => { toggleEventId(String(item.id)); setActiveLeftTab('logs') }}
                    title={`Click to filter by Event ${item.id}`}
                    style={{ cursor: 'pointer' }}
                  >
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

        {/* ── RIGHT PANEL: Questions & Submission ── */}
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
              const status = verifyStatus[q.id]
              const wrongCount = trialsCount[q.id] || 0
              const hasFreeHint = !!unlockedFreeHints[q.id]
              const hasPaidHint = !!unlockedPaidHints[q.id]

              return (
                <div
                  key={q.id}
                  className={`question-block inv-question-block ${isFilled ? 'inv-q-answered' : ''} ${
                    status?.correct ? 'inv-q-correct' : status?.correct === false ? 'inv-q-incorrect' : ''
                  }`}
                >
                  <div className="inv-q-label-row">
                    <span className="inv-q-num">{idx + 1}</span>
                    <label className="inv-q-text">{q.question_text}</label>
                    <div className="q-label-meta-cluster">
                      {!hasFreeHint ? (
                        <button
                          type="button"
                          className="btn-free-hint-sm"
                          onClick={() => handleUseFreeHint(q.id, idx)}
                          title="Get 1 Free Starter Hint for this question (0 pts penalty)"
                        >
                          🎁 Free Hint
                        </button>
                      ) : (
                        <span className="free-hint-active-pill" title="Free starter clue unlocked for this question">
                          🎁 Free Hint Unlocked
                        </span>
                      )}
                      <span className="q-points-badge">{q.points || 10} pts</span>
                    </div>
                  </div>

                  <div className="inv-input-action-row">
                    <div className="inv-input-wrap" style={{ flex: 1 }}>
                      <input
                        type="text"
                        className={`answer-input inv-answer-input ${isFilled ? 'inv-input-filled' : ''} ${
                          status?.correct ? 'inv-input-correct' : status?.correct === false ? 'inv-input-incorrect' : ''
                        }`}
                        placeholder="Enter finding (e.g. IP, username, MITRE ID)..."
                        value={val}
                        onChange={(e) => handleAnswerChange(q.id, e.target.value)}
                        required
                      />
                      {isFilled && <span className="inv-check">✓</span>}
                    </div>

                    <button
                      type="button"
                      className={`btn-verify-finding ${status?.correct ? 'verified' : ''}`}
                      onClick={() => handleVerifyFinding(q.id)}
                      disabled={verifyingId === q.id || !isFilled}
                      title="Test this finding before submitting the report"
                    >
                      {verifyingId === q.id ? 'Checking...' : status?.correct ? 'Verified ✓' : 'Verify'}
                    </button>
                  </div>

                  {/* Verification message / error badge */}
                  {status && (
                    <div className={`verify-feedback-msg ${status.correct ? 'msg-success' : 'msg-error'}`}>
                      {status.correct ? <CheckCircle2 size={13} /> : <AlertTriangle size={13} />}
                      <span>{status.message}</span>
                      {!status.correct && wrongCount > 0 && (
                        <span className="attempt-badge">Failed attempts: {wrongCount}</span>
                      )}
                    </div>
                  )}

                  {/* Free Hint Banner (if unlocked) */}
                  {hasFreeHint && (
                    <div className="unlocked-hint-box unlocked-hint-box-free" style={{ marginTop: '8px' }}>
                      <div className="unlocked-hint-header">
                        <Lightbulb size={13} className="hint-bulb-icon" />
                        <span className="hint-header-free">🎁 Free Starter Clue (0 pts deducted):</span>
                      </div>
                      <p className="unlocked-hint-text">{unlockedFreeHints[q.id]}</p>
                    </div>
                  )}

                  {/* 2-Trial Paid Forensic Hint Section (remains accessible on this same question!) */}
                  <div className="q-hint-control-row" style={{ marginTop: '8px' }}>
                    {hasPaidHint ? (
                      <div className="unlocked-hint-box">
                        <div className="unlocked-hint-header">
                          <Lightbulb size={13} className="hint-bulb-icon" />
                          <span className="hint-header-paid">💡 Forensic Walkthrough (-15 pts deduction applied):</span>
                        </div>
                        <p className="unlocked-hint-text">{unlockedPaidHints[q.id]}</p>
                      </div>
                    ) : wrongCount >= 2 ? (
                      <button
                        type="button"
                        className="btn-unlock-hint"
                        onClick={() => handleUnlockPaidHint(q.id)}
                      >
                        <Lightbulb size={13} />
                        <span>💡 Unlock Forensic Hint (-15 pts deduction)</span>
                      </button>
                    ) : (
                      <div className="hint-locked-badge" title="Trainees must attempt at least 2 incorrect findings before hint unlocks">
                        <Lock size={11} />
                        <span>Forensic hint locked (Unlocks after 2 wrong attempts: {wrongCount}/2)</span>
                      </div>
                    )}
                  </div>
                </div>
              )
            })}

            {freeHintsUsed.length > 0 && (
              <div className="hint-penalty-alert hint-free-notice">
                <CheckCircle2 size={14} style={{ color: '#10b981', flexShrink: 0 }} />
                <span>
                  <strong>Free Hints Active:</strong> You used {freeHintsUsed.length} free hint(s) (<strong>0 points deducted</strong>).
                </span>
              </div>
            )}

            {hintsUsed.length > 0 && (
              <div className="hint-penalty-alert">
                <AlertTriangle size={14} style={{ flexShrink: 0 }} />
                <span>
                  <strong>Hint Penalty Notice:</strong> You unlocked {hintsUsed.length} forensic hint(s). A total deduction of <strong>{hintsUsed.length * 15} points</strong> will be subtracted from your final score.
                </span>
              </div>
            )}

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