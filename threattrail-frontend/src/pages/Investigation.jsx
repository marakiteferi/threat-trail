import { useEffect, useState, Fragment } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import {
  AlertTriangle,
  FileText,
  Search,
  X,
  HelpCircle,
  Target,
  Check,
  ArrowLeft,
  ChevronDown,
  ChevronUp,
} from 'lucide-react'
import api from '../api'
import LogInspector from '../components/LogInspector'

const SEV_CONFIG = {
  Critical: { accent: '#bc8cff', bg: 'rgba(188,140,255,0.1)',  border: 'rgba(188,140,255,0.4)', pill: '#bc8cff' },
  High:     { accent: '#f85149', bg: 'rgba(248,81,73,0.1)',    border: 'rgba(248,81,73,0.4)',   pill: '#f85149' },
  Medium:   { accent: '#d29922', bg: 'rgba(210,153,34,0.1)',   border: 'rgba(210,153,34,0.4)',  pill: '#d29922' },
  Low:      { accent: '#3fb950', bg: 'rgba(63,185,80,0.1)',    border: 'rgba(63,185,80,0.4)',   pill: '#3fb950' },
}

export default function Investigation() {
  const { scenarioId } = useParams()
  const navigate = useNavigate()
  const [alert, setAlert]       = useState(null)
  const [logs, setLogs]         = useState([])
  const [questions, setQuestions] = useState([])
  const [answers, setAnswers]   = useState({})
  const [loading, setLoading]   = useState(true)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError]       = useState(null)
  const [searchTerm, setSearchTerm] = useState('')
  const [expandedLog, setExpandedLog] = useState(null)

  useEffect(() => {
    Promise.all([
      api.get(`/scenarios/${scenarioId}/alert`),
      api.get(`/scenarios/${scenarioId}/logs`),
      api.get(`/scenarios/${scenarioId}/questions`),
    ])
      .then(([alertRes, logsRes, questionsRes]) => {
        setAlert(alertRes.data)
        setLogs(logsRes.data)
        setQuestions(questionsRes.data)
      })
      .catch(err => setError(err.message))
      .finally(() => setLoading(false))
  }, [scenarioId])

  const handleSubmit = async (e) => {
    e.preventDefault()
    setSubmitting(true)
    try {
      const payload = {
        answers: questions.map(q => ({
          question_id: q.id,
          answer: answers[q.id] || '',
        })),
      }
      const res = await api.post(`/scenarios/${scenarioId}/submit`, payload)
      sessionStorage.setItem(`report_${scenarioId}`, JSON.stringify(res.data))
      navigate(`/report/${scenarioId}`)
    } catch (err) {
      setError(err.message)
    } finally {
      setSubmitting(false)
    }
  }

  const filteredLogs = logs.filter(log => {
    if (!searchTerm) return true
    const term = searchTerm.toLowerCase()
    return (
      String(log.event_id).includes(term) ||
      (log.source_ip && log.source_ip.toLowerCase().includes(term)) ||
      (log.username && log.username.toLowerCase().includes(term)) ||
      (log.target_host && log.target_host.toLowerCase().includes(term)) ||
      JSON.stringify(log.raw_event_data).toLowerCase().includes(term)
    )
  })

  const answeredCount = questions.filter(q => (answers[q.id] || '').trim()).length
  const totalPts = questions.reduce((s, q) => s + (q.points || 10), 0)

  if (loading) return (
    <div className="db-loading">
      <div className="db-loading-spinner" />
      <span>Loading investigation data…</span>
    </div>
  )
  if (error) return (
    <div className="inv-error">
      <AlertTriangle size={16} />
      <span>{error}</span>
    </div>
  )

  const sev = alert?.severity || 'High'
  const sevCfg = SEV_CONFIG[sev] || SEV_CONFIG.High

  return (
    <div className="investigation-v2">

      {/* ── Alert Banner ── */}
      {alert && (
        <div className="inv-alert-banner" style={{ background: sevCfg.bg, borderColor: sevCfg.border }}>
          <div className="inv-alert-left">
            <span className="inv-sev-pill" style={{ background: sevCfg.accent }}>
              {sev.toUpperCase()}
            </span>
            <div className="inv-alert-body">
              <span className="inv-alert-label">
                <AlertTriangle size={12} />
                Active Alert
              </span>
              <span className="inv-alert-title">{alert.title}</span>
            </div>
          </div>
          <div className="inv-alert-right">
            <span className="inv-log-count">
              <FileText size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
              {logs.length} events loaded
            </span>
            <Link to="/" className="inv-back-link">
              <ArrowLeft size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
              Dashboard
            </Link>
          </div>
        </div>
      )}

      {/* ── Two-Column Layout ── */}
      <div className="investigation-layout">

        {/* ── Left: Log Viewer ── */}
        <div className="log-panel">
          <div className="inv-panel-header">
            <div className="inv-panel-title">
              <FileText size={17} className="inv-panel-icon-svg" />
              <h3>Windows Event Logs</h3>
              <span className="inv-log-counter">{filteredLogs.length}</span>
            </div>
            <div className="inv-search-wrap">
              <Search size={14} className="inv-search-icon" />
              <input
                type="text"
                placeholder="Filter events, IPs, usernames…"
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                className="inv-search-input"
              />
              {searchTerm && (
                <button className="inv-search-clear" onClick={() => setSearchTerm('')} title="Clear filter">
                  <X size={13} />
                </button>
              )}
            </div>
          </div>

          <div className="log-table-wrapper">
            <table className="log-table">
              <thead>
                <tr>
                  <th style={{ width: '22%' }}>Timestamp</th>
                  <th style={{ width: '13%' }}>Event ID</th>
                  <th style={{ width: '22%' }}>Username</th>
                  <th style={{ width: '21%' }}>Source IP</th>
                  <th style={{ width: '22%' }}>Host</th>
                </tr>
              </thead>
              <tbody>
                {filteredLogs.length === 0 && (
                  <tr>
                    <td colSpan="5" style={{ textAlign: 'center', padding: '32px', color: 'var(--text-dim)' }}>
                      No events match your filter.
                    </td>
                  </tr>
                )}
                {filteredLogs.map(log => (
                  <Fragment key={log.id}>
                    <tr
                      className={`log-row inv-log-row ${log.event_id === 4624 ? 'success-event' : 'failure-event'} ${expandedLog === log.id ? 'log-row-expanded' : ''}`}
                      onClick={() => setExpandedLog(expandedLog === log.id ? null : log.id)}
                    >
                      <td title={new Date(log.timestamp).toLocaleString()}>
                        <span className="inv-ts-date">{new Date(log.timestamp).toLocaleDateString()}</span>
                        <span className="inv-ts-time">{new Date(log.timestamp).toLocaleTimeString()}</span>
                      </td>
                      <td>
                        <span className={`event-badge ${log.event_id === 4624 ? 'event-success' : 'event-failure'}`}>
                          {log.event_id}
                        </span>
                      </td>
                      <td>
                        <span className="inv-username">{log.username || '—'}</span>
                      </td>
                      <td>
                        <span className="inv-ip">{log.source_ip || '—'}</span>
                      </td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                          <span className="inv-host">{log.target_host || '—'}</span>
                          <span style={{ opacity: 0.5 }}>
                            {expandedLog === log.id ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
                          </span>
                        </div>
                      </td>
                    </tr>
                    {expandedLog === log.id && (
                      <tr className="log-detail-row">
                        <td colSpan="5">
                          <LogInspector log={log} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── Right: Q&A Panel ── */}
        <div className="questions-panel inv-qa-panel">
          {/* Progress Header */}
          <div className="inv-qa-header">
            <div className="inv-qa-title">
              <HelpCircle size={16} />
              <h3>Investigation Questions</h3>
            </div>
            <div className="inv-progress-wrap">
              <div className="inv-progress-bar">
                <div
                  className="inv-progress-fill"
                  style={{ width: `${questions.length ? (answeredCount / questions.length) * 100 : 0}%` }}
                />
              </div>
              <span className="inv-progress-label">{answeredCount}/{questions.length} answered</span>
            </div>
            <span className="total-scenario-pts">
              <Target size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
              {totalPts} pts
            </span>
          </div>

          <form onSubmit={handleSubmit} className="inv-qa-form">
            {questions.map((q, i) => {
              const answered = !!(answers[q.id] || '').trim()
              return (
                <div key={q.id} className={`question-block inv-question-block ${answered ? 'inv-q-answered' : ''}`}>
                  <div className="inv-q-label-row">
                    <div className="inv-q-num">{i + 1}</div>
                    <label className="inv-q-text">{q.question_text}</label>
                    <span className="q-points-badge">+{q.points || 10} pts</span>
                  </div>
                  <div className="inv-input-wrap">
                    {answered && (
                      <span className="inv-check">
                        <Check size={14} />
                      </span>
                    )}
                    <input
                      type="text"
                      value={answers[q.id] || ''}
                      onChange={e => setAnswers(prev => ({ ...prev, [q.id]: e.target.value }))}
                      placeholder="Type your answer…"
                      className={`answer-input inv-answer-input ${answered ? 'inv-input-filled' : ''}`}
                    />
                  </div>
                </div>
              )
            })}

            <button
              type="submit"
              className="inv-submit-btn"
              disabled={submitting}
            >
              {submitting ? (
                <><span className="inv-spinner" /> Grading…</>
              ) : (
                <>Submit Investigation →</>
              )}
            </button>
          </form>
        </div>
      </div>
    </div>
  )
}
