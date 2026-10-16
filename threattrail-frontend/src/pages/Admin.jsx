import { useState, useEffect } from 'react'
import { Link } from 'react-router-dom'
import api from '../api'
import {
  ShieldCheck,
  Layers,
  PlusCircle,
  FileText,
  HelpCircle,
  Edit3,
  Search,
  Trash2,
  CheckCircle2,
  ArrowRight,
  Target,
  FolderOpen,
  AlertTriangle,
  X,
  Save
} from 'lucide-react'

export default function Admin() {
  const [activeTab, setActiveTab] = useState('manage') // 'manage' | 'create'
  
  // Scenarios list & stats
  const [scenarios, setScenarios] = useState([])
  const [stats, setStats] = useState(null)
  const [loadingScenarios, setLoadingScenarios] = useState(true)
  const [filterStatus, setFilterStatus] = useState('all') // 'all' | 'published' | 'draft'
  const [searchTerm, setSearchTerm] = useState('')

  // Toast feedback
  const [toast, setToast] = useState(null)

  // Creation form state
  const [createName, setCreateName] = useState('')
  const [createDesc, setCreateDesc] = useState('')
  const [createMitre, setCreateMitre] = useState('')
  const [createStatus, setCreateStatus] = useState('Published')
  const [createAlertTitle, setCreateAlertTitle] = useState('')
  const [createAlertSeverity, setCreateAlertSeverity] = useState('High')
  const [createQuestions, setCreateQuestions] = useState([{ q: '', a: '', points: 10 }])
  const [createFile, setCreateFile] = useState(null)
  const [isSubmitting, setIsSubmitting] = useState(false)
  const [submitStep, setSubmitStep] = useState('')
  const [createSuccessData, setCreateSuccessData] = useState(null)
  const [createError, setCreateError] = useState('')

  // Edit Modal state
  const [editingScenario, setEditingScenario] = useState(null)
  const [editName, setEditName] = useState('')
  const [editDesc, setEditDesc] = useState('')
  const [editMitre, setEditMitre] = useState('')
  const [editStatus, setEditStatus] = useState('Draft')
  const [editAlertTitle, setEditAlertTitle] = useState('')
  const [editAlertSeverity, setEditAlertSeverity] = useState('High')
  const [editQuestions, setEditQuestions] = useState([])
  const [editFile, setEditFile] = useState(null)
  const [isSavingEdit, setIsSavingEdit] = useState(false)
  const [editError, setEditError] = useState('')

  // Delete confirmation modal state
  const [deletingScenario, setDeletingScenario] = useState(null)
  const [isDeleting, setIsDeleting] = useState(false)

  const showToast = (message, type = 'success') => {
    setToast({ message, type })
    setTimeout(() => {
      setToast(null)
    }, 4500)
  }

  // Fetch scenarios and stats
  const loadAdminData = async () => {
    setLoadingScenarios(true)
    try {
      const [scenariosRes, statsRes] = await Promise.all([
        api.get('/admin/scenarios'),
        api.get('/admin/stats'),
      ])
      setScenarios(scenariosRes.data)
      setStats(statsRes.data)
    } catch (err) {
      showToast(`Failed to load data: ${err.message}`, 'error')
    } finally {
      setLoadingScenarios(false)
    }
  }

  useEffect(() => {
    loadAdminData()
  }, [])

  // ── Toggle Scenario Status (Publish / Draft) ───────────────────────────────
  const handleToggleStatus = async (scenario) => {
    const newStatus = scenario.status === 'Published' ? 'Draft' : 'Published'
    try {
      await api.patch(`/admin/scenarios/${scenario.id}/status`, { status: newStatus })
      setScenarios(prev =>
        prev.map(s => (s.id === scenario.id ? { ...s, status: newStatus } : s))
      )
      if (stats) {
        setStats({
          ...stats,
          published_scenarios:
            newStatus === 'Published'
              ? stats.published_scenarios + 1
              : stats.published_scenarios - 1,
          draft_scenarios:
            newStatus === 'Draft'
              ? stats.draft_scenarios + 1
              : stats.draft_scenarios - 1,
        })
      }
      showToast(`Scenario marked as ${newStatus}!`)
    } catch (err) {
      showToast(`Failed to update status: ${err.message}`, 'error')
    }
  }

  // ── Create Scenario Flow ───────────────────────────────────────────────────
  const handleAddCreateQuestion = () => {
    setCreateQuestions([...createQuestions, { q: '', a: '', points: 10 }])
  }

  const handleCreateQuestionChange = (i, field, val) => {
    const updated = [...createQuestions]
    updated[i][field] = val
    setCreateQuestions(updated)
  }

  const handleRemoveCreateQuestion = (i) => {
    if (createQuestions.length > 1) {
      setCreateQuestions(createQuestions.filter((_, idx) => idx !== i))
    }
  }

  const handleCreateSubmit = async (e) => {
    e.preventDefault()
    setIsSubmitting(true)
    setCreateError('')
    setCreateSuccessData(null)

    try {
      // Step 1: Create Scenario, Alert, and Questions in a single atomic transaction
      setSubmitStep('Step 1/2: Registering scenario, alert, and questions atomically...')

      const questionsPayload = createQuestions
        .filter(q => q.q && q.a)
        .map(q => ({
          question_text: q.q.trim(),
          correct_answer: q.a.trim(),
          points: parseInt(q.points) || 10,
        }))

      const totalPts = questionsPayload.reduce((sum, q) => sum + (q.points || 10), 0)

      const fullRes = await api.post('/admin/scenarios/full', {
        name: createName,
        description: createDesc,
        mitre_technique: createMitre,
        status: createStatus,
        alert_title: createAlertTitle || `Detection Alert: ${createName}`,
        alert_severity: createAlertSeverity,
        questions: questionsPayload,
      })

      const scId = fullRes.data.id
      const questionsAdded = fullRes.data.questions?.length || questionsPayload.length

      // Step 2: Upload Logs if ZIP archive selected
      let logsInserted = 0
      if (createFile) {
        setSubmitStep('Step 2/2: Uploading and ingesting Windows Event logs archive...')
        const formData = new FormData()
        formData.append('file', createFile)

        const uploadRes = await api.post(`/admin/scenarios/${scId}/upload-logs`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        })
        logsInserted = uploadRes.data?.logs_inserted || 0
      }

      // Record success details
      setCreateSuccessData({
        id: scId,
        name: createName,
        status: createStatus,
        mitre: createMitre,
        alertTitle: createAlertTitle,
        questionsCount: questionsAdded,
        totalPoints: totalPts,
        logsCount: logsInserted,
      })

      showToast(`Scenario "${createName}" (${totalPts} pts) created successfully in atomic transaction!`)

      // Reset form fields
      setCreateName('')
      setCreateDesc('')
      setCreateMitre('')
      setCreateAlertTitle('')
      setCreateAlertSeverity('High')
      setCreateQuestions([{ q: '', a: '', points: 10 }])
      setCreateFile(null)

      // Refresh scenarios list
      loadAdminData()

    } catch (err) {
      setCreateError(err.response?.data?.detail || err.message)
      showToast(`Creation failed: ${err.message}`, 'error')
    } finally {
      setIsSubmitting(false)
      setSubmitStep('')
    }
  }

  // ── Edit Scenario Flow ─────────────────────────────────────────────────────
  const openEditModal = async (scenario) => {
    setEditError('')
    setEditFile(null)
    setIsSavingEdit(false)

    try {
      const res = await api.get(`/admin/scenarios/${scenario.id}`)
      const detail = res.data
      setEditingScenario(detail)
      setEditName(detail.name)
      setEditDesc(detail.description)
      setEditMitre(detail.mitre_technique)
      setEditStatus(detail.status || 'Draft')
      setEditAlertTitle(detail.alert ? detail.alert.title : '')
      setEditAlertSeverity(detail.alert ? detail.alert.severity : 'High')
      setEditQuestions(
        detail.questions && detail.questions.length > 0
          ? detail.questions.map(q => ({
              question_text: q.question_text,
              correct_answer: q.correct_answer,
              points: q.points ?? 10,
            }))
          : [{ question_text: '', correct_answer: '', points: 10 }]
      )
    } catch (err) {
      showToast(`Failed to load scenario details: ${err.message}`, 'error')
    }
  }

  const handleSaveEdit = async (e) => {
    e.preventDefault()
    if (!editingScenario) return
    setIsSavingEdit(true)
    setEditError('')

    try {
      // 1. Full update payload
      const payload = {
        name: editName,
        description: editDesc,
        mitre_technique: editMitre,
        status: editStatus,
        alert_title: editAlertTitle,
        alert_severity: editAlertSeverity,
        questions: editQuestions
          .filter(q => q.question_text.trim() && q.correct_answer.trim())
          .map(q => ({
            question_text: q.question_text,
            correct_answer: q.correct_answer,
            points: parseInt(q.points) || 10,
          })),
      }

      await api.put(`/admin/scenarios/${editingScenario.id}/full`, payload)

      // 2. Upload replacement logs if file provided
      if (editFile) {
        const formData = new FormData()
        formData.append('file', editFile)
        await api.post(`/admin/scenarios/${editingScenario.id}/upload-logs`, formData, {
          headers: { 'Content-Type': 'multipart/form-data' },
        })
      }

      showToast(`Scenario "${editName}" updated successfully!`)
      setEditingScenario(null)
      loadAdminData()
    } catch (err) {
      setEditError(err.response?.data?.detail || err.message)
      showToast(`Failed to save: ${err.message}`, 'error')
    } finally {
      setIsSavingEdit(false)
    }
  }

  // ── Delete Scenario Flow ───────────────────────────────────────────────────
  const handleDeleteScenario = async () => {
    if (!deletingScenario) return
    setIsDeleting(true)
    try {
      await api.delete(`/admin/scenarios/${deletingScenario.id}`)
      showToast(`Scenario "${deletingScenario.name}" was deleted!`)
      setDeletingScenario(null)
      loadAdminData()
    } catch (err) {
      showToast(`Failed to delete: ${err.message}`, 'error')
    } finally {
      setIsDeleting(false)
    }
  }

  // Filtered scenarios
  const filteredScenarios = scenarios.filter(s => {
    if (filterStatus === 'published' && s.status !== 'Published') return false
    if (filterStatus === 'draft' && s.status !== 'Draft') return false
    if (searchTerm) {
      const term = searchTerm.toLowerCase()
      const matchName = s.name.toLowerCase().includes(term)
      const matchMitre = s.mitre_technique.toLowerCase().includes(term)
      const matchDesc = s.description.toLowerCase().includes(term)
      if (!matchName && !matchMitre && !matchDesc) return false
    }
    return true
  })

  return (
    <div className="admin-page-container">
      {/* Toast Notification */}
      {toast && (
        <div className={`admin-toast toast-${toast.type}`}>
          <span>{toast.message}</span>
          <button className="toast-close" onClick={() => setToast(null)}>×</button>
        </div>
      )}

      {/* Admin Top Header & KPI Summary */}
      <div className="admin-header-strip">
        <div>
          <h2>
            <ShieldCheck size={22} style={{ verticalAlign: 'middle', marginRight: '8px' }} color="#00ffcc" />
            SOC Admin & Scenario Management
          </h2>
          <p className="admin-subtitle">
            Manage investigation training scenarios, ingest Windows Event logs, and publish scenarios for SOC trainees.
          </p>
        </div>
        <div className="admin-nav-tabs">
          <button
            className={`admin-nav-btn ${activeTab === 'manage' ? 'active' : ''}`}
            onClick={() => setActiveTab('manage')}
          >
            <Layers size={16} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
            Manage Scenarios ({scenarios.length})
          </button>
          <button
            className={`admin-nav-btn ${activeTab === 'create' ? 'active' : ''}`}
            onClick={() => {
              setActiveTab('create')
              setCreateSuccessData(null)
            }}
          >
            <PlusCircle size={16} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
            Create New Scenario
          </button>
        </div>
      </div>

      {/* KPI Cards Strip */}
      {stats && (
        <div className="admin-stats-grid">
          <div className="stat-card">
            <span className="stat-label">Total Scenarios</span>
            <span className="stat-number">{stats.total_scenarios}</span>
          </div>
          <div className="stat-card stat-success">
            <span className="stat-label">Published (Live for Trainees)</span>
            <span className="stat-number">{stats.published_scenarios}</span>
          </div>
          <div className="stat-card stat-warning">
            <span className="stat-label">Drafts (In Progress)</span>
            <span className="stat-number">{stats.draft_scenarios}</span>
          </div>
          <div className="stat-card stat-info">
            <span className="stat-label">Total Log Events</span>
            <span className="stat-number">{stats.total_logs.toLocaleString()}</span>
          </div>
        </div>
      )}

      {/* ── TAB 1: MANAGE SCENARIOS ────────────────────────────────────────── */}
      {activeTab === 'manage' && (
        <div className="admin-manage-section">
          <div className="manage-controls-bar">
            <div className="filter-group">
              <button
                className={`filter-btn ${filterStatus === 'all' ? 'active' : ''}`}
                onClick={() => setFilterStatus('all')}
              >
                All ({scenarios.length})
              </button>
              <button
                className={`filter-btn ${filterStatus === 'published' ? 'active' : ''}`}
                onClick={() => setFilterStatus('published')}
              >
                Published ({scenarios.filter(s => s.status === 'Published').length})
              </button>
              <button
                className={`filter-btn ${filterStatus === 'draft' ? 'active' : ''}`}
                onClick={() => setFilterStatus('draft')}
              >
                Drafts ({scenarios.filter(s => s.status === 'Draft').length})
              </button>
            </div>

            <div className="search-wrap">
              <input
                type="text"
                placeholder="Search scenarios or MITRE ID..."
                value={searchTerm}
                onChange={e => setSearchTerm(e.target.value)}
                className="admin-search-input"
              />
            </div>
          </div>

          {loadingScenarios ? (
            <div className="loading">Loading scenarios...</div>
          ) : filteredScenarios.length === 0 ? (
            <div className="empty-scenarios-card">
              <p>No scenarios found matching your criteria.</p>
              <button
                className="btn btn-primary"
                onClick={() => setActiveTab('create')}
              >
                + Create a Scenario Now
              </button>
            </div>
          ) : (
            <div className="scenario-admin-grid">
              {filteredScenarios.map(sc => (
                <div key={sc.id} className="scenario-admin-card">
                  <div className="sc-card-top">
                    <div className="sc-header-row">
                      <div className="sc-title-block">
                        <span className="sc-id-badge">#{sc.id}</span>
                        <h3>{sc.name}</h3>
                      </div>
                      <div className="sc-status-badge-wrap">
                        <span className={`status-pill ${sc.status === 'Published' ? 'status-published' : 'status-draft'}`}>
                          {sc.status}
                        </span>
                      </div>
                    </div>

                    <div className="sc-badges-row">
                      <span className="mitre-badge">{sc.mitre_technique}</span>
                      {sc.alert && (
                        <span className={`severity-badge-sm severity-${sc.alert.severity?.toLowerCase()}`}>
                          {sc.alert.severity} Severity
                        </span>
                      )}
                      <span className="metric-chip"><FileText size={13} style={{ verticalAlign: 'middle', marginRight: '4px' }} />{sc.logs_count} Logs</span>
                      <span className="metric-chip"><HelpCircle size={13} style={{ verticalAlign: 'middle', marginRight: '4px' }} />{sc.questions_count} Questions</span>
                    </div>

                    <p className="sc-card-desc">{sc.description}</p>
                    {sc.alert && (
                      <div className="sc-alert-preview">
                        <strong>Alert:</strong> {sc.alert.title}
                      </div>
                    )}
                  </div>

                  <div className="sc-card-actions">
                    <button
                      className={`btn-action btn-status-toggle ${sc.status === 'Published' ? 'btn-unpublish' : 'btn-publish'}`}
                      onClick={() => handleToggleStatus(sc)}
                      title={sc.status === 'Published' ? 'Unpublish to Draft' : 'Publish to Trainees'}
                    >
                      {sc.status === 'Published' ? 'Unpublish' : 'Publish'}
                    </button>

                    <button
                      className="btn-action btn-edit"
                      onClick={() => openEditModal(sc)}
                    >
                      <Edit3 size={14} style={{ verticalAlign: 'middle', marginRight: '4px' }} /> Edit
                    </button>

                    <Link
                      to={`/investigate/${sc.id}`}
                      className="btn-action btn-preview"
                      title="Test investigation view as analyst"
                    >
                      <Search size={14} style={{ verticalAlign: 'middle', marginRight: '4px' }} /> Investigate
                    </Link>

                    <button
                      className="btn-action btn-delete"
                      onClick={() => setDeletingScenario(sc)}
                      title="Delete Scenario"
                    >
                      <Trash2 size={14} />
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── TAB 2: CREATE SCENARIO ─────────────────────────────────────────── */}
      {activeTab === 'create' && (
        <div className="admin-create-section">
          {/* Unmissable Success Banner / Feedback */}
          {createSuccessData && (
            <div className="scenario-creation-success-box">
              <div className="success-banner-header">
                <span className="success-icon">
                  <CheckCircle2 size={36} color="#10b981" />
                </span>
                <div>
                  <h3>Scenario Created Successfully!</h3>
                  <p>
                    <strong>"{createSuccessData.name}"</strong> has been saved and is currently marked as{' '}
                    <span className={`status-pill ${createSuccessData.status === 'Published' ? 'status-published' : 'status-draft'}`}>
                      {createSuccessData.status}
                    </span>.
                  </p>
                </div>
              </div>

              <div className="success-meta-strip">
                <div>MITRE Technique: <strong>{createSuccessData.mitre}</strong></div>
                <div>Questions Configured: <strong>{createSuccessData.questionsCount}</strong></div>
                <div>Total Score Points: <strong>{createSuccessData.totalPoints || 0} pts</strong></div>
                <div>Log Events Ingested: <strong>{createSuccessData.logsCount}</strong></div>
              </div>

              <div className="success-actions-row">
                <button
                  className="btn btn-primary"
                  onClick={() => setActiveTab('manage')}
                >
                  <Layers size={16} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
                  View in Scenario Manager
                </button>
                <Link
                  to={`/investigate/${createSuccessData.id}`}
                  className="btn btn-success"
                >
                  <Search size={16} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
                  Test Investigation Interface
                  <ArrowRight size={14} style={{ verticalAlign: 'middle', marginLeft: '6px' }} />
                </Link>
                <button
                  className="btn btn-secondary"
                  onClick={() => setCreateSuccessData(null)}
                >
                  <PlusCircle size={16} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
                  Create Another Scenario
                </button>
              </div>
            </div>
          )}

          {/* Creation Form Container */}
          <div className="admin-form-panel">
            <div className="panel-title-area">
              <h3>Create New Attack Scenario</h3>
              <p>Configure detection scenario details, investigation Q&A, and ingest raw event datasets.</p>
            </div>

            {createError && (
              <div className="admin-error-box">
                <strong>Error:</strong> {createError}
              </div>
            )}

            <form onSubmit={handleCreateSubmit}>
              {/* 1. Scenario Meta */}
              <div className="form-section-card">
                <div className="section-title">
                  <span className="step-num">1</span>
                  <h4>Scenario Information & Publication Status</h4>
                </div>

                <div className="form-row">
                  <div className="form-field flex-2">
                    <label>Scenario Name *</label>
                    <input
                      className="admin-input"
                      placeholder="e.g. Empire Mimikatz LSASS Dump"
                      value={createName}
                      onChange={e => setCreateName(e.target.value)}
                      required
                    />
                  </div>
                  <div className="form-field flex-1">
                    <label>MITRE ATT&CK Technique *</label>
                    <input
                      className="admin-input"
                      placeholder="e.g. T1003.001"
                      value={createMitre}
                      onChange={e => setCreateMitre(e.target.value)}
                      required
                    />
                  </div>
                  <div className="form-field flex-1">
                    <label>Publication Status</label>
                    <select
                      className="admin-input"
                      value={createStatus}
                      onChange={e => setCreateStatus(e.target.value)}
                    >
                      <option value="Published">Published (Live for Trainees)</option>
                      <option value="Draft">Draft (Hidden)</option>
                    </select>
                  </div>
                </div>

                <div className="form-field">
                  <label>Scenario Description & Scenario Background *</label>
                  <textarea
                    className="admin-input"
                    style={{ minHeight: '85px' }}
                    placeholder="Provide context on the attacker behavior, adversary objective, and training guidance..."
                    value={createDesc}
                    onChange={e => setCreateDesc(e.target.value)}
                    required
                  />
                </div>
              </div>

              {/* 2. Alert Info */}
              <div className="form-section-card">
                <div className="section-title">
                  <span className="step-num">2</span>
                  <h4>Predefined SIEM / SOC Alert</h4>
                </div>

                <div className="form-row">
                  <div className="form-field flex-3">
                    <label>Alert Title *</label>
                    <input
                      className="admin-input"
                      placeholder="e.g. High: Suspicious LSASS Memory Read Attempt"
                      value={createAlertTitle}
                      onChange={e => setCreateAlertTitle(e.target.value)}
                      required
                    />
                  </div>
                  <div className="form-field flex-1">
                    <label>Severity Level</label>
                    <select
                      className="admin-input"
                      value={createAlertSeverity}
                      onChange={e => setCreateAlertSeverity(e.target.value)}
                    >
                      <option value="Low">Low</option>
                      <option value="Medium">Medium</option>
                      <option value="High">High</option>
                      <option value="Critical">Critical</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* 3. Investigation Questions */}
              <div className="form-section-card">
                <div className="section-title" style={{ justifyContent: 'space-between' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                    <span className="step-num">3</span>
                    <h4>Investigation Questions & Scoring (Points)</h4>
                  </div>
                  <span className="total-scenario-pts">
                    <Target size={14} style={{ verticalAlign: 'middle', marginRight: '5px' }} /> Total: {createQuestions.reduce((sum, q) => sum + (parseInt(q.points) || 0), 0)} pts
                  </span>
                </div>
                <p className="section-hint">
                  Provide questions for the analyst to solve, expected exact answers, and point value per question.
                </p>

                {createQuestions.map((q, i) => (
                  <div key={i} className="question-input-row">
                    <span className="q-index-pill">Q{i + 1}</span>
                    <input
                      className="admin-input flex-3"
                      placeholder="Question (e.g. What is the compromised user account?)"
                      value={q.q}
                      onChange={e => handleCreateQuestionChange(i, 'q', e.target.value)}
                      required
                    />
                    <input
                      className="admin-input flex-2"
                      placeholder="Expected Answer (e.g. wardog)"
                      value={q.a}
                      onChange={e => handleCreateQuestionChange(i, 'a', e.target.value)}
                      required
                    />
                    <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                      <input
                        type="number"
                        min="1"
                        max="100"
                        className="admin-input"
                        style={{ width: '64px', textAlign: 'center' }}
                        value={q.points ?? 10}
                        onChange={e => handleCreateQuestionChange(i, 'points', e.target.value)}
                        required
                        title="Question points"
                      />
                      <span style={{ fontSize: '0.8rem', color: 'var(--text-dim)', userSelect: 'none' }}>pts</span>
                    </div>
                    {createQuestions.length > 1 && (
                      <button
                        type="button"
                        className="btn-remove-q"
                        onClick={() => handleRemoveCreateQuestion(i)}
                        title="Remove question"
                      >
                        <X size={14} />
                      </button>
                    )}
                  </div>
                ))}

                <button
                  type="button"
                  className="btn btn-secondary btn-sm"
                  onClick={handleAddCreateQuestion}
                >
                  + Add Another Question
                </button>
              </div>

              {/* 4. Windows Event Logs Ingestion */}
              <div className="form-section-card">
                <div className="section-title">
                  <span className="step-num">4</span>
                  <h4>Windows Event Log Dataset (.zip)</h4>
                </div>
                <p className="section-hint">
                  Upload a ZIP archive containing JSON or JSONL event logs (e.g. Mordor datasets or exported Windows Event logs).
                </p>
                <div className="file-upload-zone">
                  <input
                    type="file"
                    accept=".zip"
                    id="log-file-input"
                    onChange={e => setCreateFile(e.target.files[0])}
                  />
                  {createFile && (
                    <div className="selected-file-info">
                      <FolderOpen size={16} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
                      Selected: <strong>{createFile.name}</strong> ({(createFile.size / 1024).toFixed(1)} KB)
                    </div>
                  )}
                </div>
              </div>

              {/* Progress step message */}
              {isSubmitting && (
                <div className="submission-progress-box">
                  <div className="spinner"></div>
                  <span>{submitStep}</span>
                </div>
              )}

              {/* Submit Button */}
              <div className="form-actions-bar">
                <button
                  type="submit"
                  className="btn btn-primary btn-lg"
                  disabled={isSubmitting}
                >
                  {isSubmitting ? 'Creating Scenario...' : (
                    <>
                      <Save size={16} style={{ verticalAlign: 'middle', marginRight: '6px' }} />
                      Create & Save Scenario
                    </>
                  )}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── MODAL: EDIT SCENARIO ────────────────────────────────────────────── */}
      {editingScenario && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>
                <Edit3 size={18} color="#00ffcc" style={{ verticalAlign: 'middle', marginRight: '8px' }} />
                Edit Scenario: {editingScenario.name}
              </h3>
              <button
                className="modal-close-btn"
                onClick={() => setEditingScenario(null)}
              >
                <X size={18} />
              </button>
            </div>

            {editError && (
              <div className="admin-error-box" style={{ margin: '16px 24px 0' }}>
                {editError}
              </div>
            )}

            <form onSubmit={handleSaveEdit} className="modal-form">
              <div className="modal-scroll-area">
                {/* Basic Meta */}
                <div className="form-row">
                  <div className="form-field flex-2">
                    <label>Scenario Name</label>
                    <input
                      className="admin-input"
                      value={editName}
                      onChange={e => setEditName(e.target.value)}
                      required
                    />
                  </div>
                  <div className="form-field flex-1">
                    <label>MITRE Technique</label>
                    <input
                      className="admin-input"
                      value={editMitre}
                      onChange={e => setEditMitre(e.target.value)}
                      required
                    />
                  </div>
                  <div className="form-field flex-1">
                    <label>Status</label>
                    <select
                      className="admin-input"
                      value={editStatus}
                      onChange={e => setEditStatus(e.target.value)}
                    >
                      <option value="Published">Published</option>
                      <option value="Draft">Draft</option>
                    </select>
                  </div>
                </div>

                <div className="form-field">
                  <label>Description</label>
                  <textarea
                    className="admin-input"
                    style={{ minHeight: '80px' }}
                    value={editDesc}
                    onChange={e => setEditDesc(e.target.value)}
                    required
                  />
                </div>

                {/* Alert */}
                <div className="form-row">
                  <div className="form-field flex-3">
                    <label>Alert Title</label>
                    <input
                      className="admin-input"
                      value={editAlertTitle}
                      onChange={e => setEditAlertTitle(e.target.value)}
                      required
                    />
                  </div>
                  <div className="form-field flex-1">
                    <label>Severity</label>
                    <select
                      className="admin-input"
                      value={editAlertSeverity}
                      onChange={e => setEditAlertSeverity(e.target.value)}
                    >
                      <option value="Low">Low</option>
                      <option value="Medium">Medium</option>
                      <option value="High">High</option>
                      <option value="Critical">Critical</option>
                    </select>
                  </div>
                </div>

                {/* Questions */}
                <div className="edit-questions-block">
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                    <label style={{ margin: 0 }}>Investigation Questions & Answers ({editQuestions.length})</label>
                    <span className="total-scenario-pts">
                      <Target size={14} style={{ verticalAlign: 'middle', marginRight: '5px' }} />
                      Total: {editQuestions.reduce((sum, q) => sum + (parseInt(q.points) || 0), 0)} pts
                    </span>
                  </div>
                  {editQuestions.map((q, i) => (
                    <div key={i} className="question-input-row">
                      <span className="q-index-pill">Q{i + 1}</span>
                      <input
                        className="admin-input flex-3"
                        placeholder="Question text"
                        value={q.question_text}
                        onChange={e => {
                          const updated = [...editQuestions]
                          updated[i].question_text = e.target.value
                          setEditQuestions(updated)
                        }}
                        required
                      />
                      <input
                        className="admin-input flex-2"
                        placeholder="Correct answer"
                        value={q.correct_answer}
                        onChange={e => {
                          const updated = [...editQuestions]
                          updated[i].correct_answer = e.target.value
                          setEditQuestions(updated)
                        }}
                        required
                      />
                      <div style={{ display: 'flex', alignItems: 'center', gap: '4px' }}>
                        <input
                          type="number"
                          min="1"
                          max="100"
                          className="admin-input"
                          style={{ width: '64px', textAlign: 'center' }}
                          value={q.points ?? 10}
                          onChange={e => {
                            const updated = [...editQuestions]
                            updated[i].points = e.target.value
                            setEditQuestions(updated)
                          }}
                          required
                          title="Question points"
                        />
                        <span style={{ fontSize: '0.8rem', color: 'var(--text-dim)', userSelect: 'none' }}>pts</span>
                      </div>
                      {editQuestions.length > 1 && (
                        <button
                          type="button"
                          className="btn-remove-q"
                          onClick={() => setEditQuestions(editQuestions.filter((_, idx) => idx !== i))}
                        >
                          <X size={14} />
                        </button>
                      )}
                    </div>
                  ))}
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => setEditQuestions([...editQuestions, { question_text: '', correct_answer: '', points: 10 }])}
                  >
                    + Add Question
                  </button>
                </div>

                {/* Re-upload logs */}
                <div className="edit-logs-block">
                  <label>Replace Log Dataset (Optional)</label>
                  <p className="section-hint">Upload a new ZIP file only if you wish to overwrite the current logs ({editingScenario.logs_count} existing).</p>
                  <input
                    type="file"
                    accept=".zip"
                    onChange={e => setEditFile(e.target.files[0])}
                  />
                  {editFile && (
                    <span className="text-dim">
                      <FolderOpen size={14} style={{ verticalAlign: 'middle', marginRight: '4px' }} />
                      Selected: {editFile.name}
                    </span>
                  )}
                </div>
              </div>

              <div className="modal-footer">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setEditingScenario(null)}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="btn btn-primary"
                  disabled={isSavingEdit}
                >
                  {isSavingEdit ? 'Saving Changes...' : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* ── MODAL: DELETE CONFIRMATION ──────────────────────────────────────── */}
      {deletingScenario && (
        <div className="modal-backdrop">
          <div className="modal-card modal-sm">
            <div className="modal-header">
              <h3>
                <AlertTriangle size={20} color="#ef4444" style={{ verticalAlign: 'middle', marginRight: '8px' }} />
                Confirm Delete
              </h3>
              <button
                className="modal-close-btn"
                onClick={() => setDeletingScenario(null)}
              >
                <X size={18} />
              </button>
            </div>
            <div className="modal-body-padding">
              <p>
                Are you sure you want to permanently delete scenario{' '}
                <strong>"{deletingScenario.name}"</strong>?
              </p>
              <p className="text-dim" style={{ marginTop: '8px', fontSize: '0.9rem' }}>
                This will delete the scenario, associated alerts, all {deletingScenario.logs_count || 0} event logs, and all trainee scores.
              </p>
            </div>
            <div className="modal-footer">
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => setDeletingScenario(null)}
                disabled={isDeleting}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-danger"
                onClick={handleDeleteScenario}
                disabled={isDeleting}
              >
                {isDeleting ? 'Deleting...' : 'Yes, Delete Scenario'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
