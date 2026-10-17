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
  Trash2,
  CheckCircle2,
  X
} from 'lucide-react'

export default function Admin() {
  const [activeTab, setActiveTab] = useState('manage')
  const [scenarios, setScenarios] = useState([])
  const [stats, setStats] = useState(null)
  const [loadingScenarios, setLoadingScenarios] = useState(true)
  const [filterStatus, setFilterStatus] = useState('all')
  const [searchTerm, setSearchTerm] = useState('')
  const [toast, setToast] = useState(null)

  // Creation form state
  const [createName, setCreateName] = useState('')
  const [createDesc, setCreateDesc] = useState('')
  const [createMitre, setCreateMitre] = useState('')
  const [createStatus, setCreateStatus] = useState('Published')
  const [createAlertTitle, setCreateAlertTitle] = useState('')
  const [createAlertSeverity, setCreateAlertSeverity] = useState('High')
  const [createSigmaRule, setCreateSigmaRule] = useState('')
  const [createQuestions, setCreateQuestions] = useState([
    { q: '', a: '', explanation: '', points: 10 }
  ])
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
  const [editSigmaRule, setEditSigmaRule] = useState('')
  const [editQuestions, setEditQuestions] = useState([])
  const [editFile, setEditFile] = useState(null)
  const [isSavingEdit, setIsSavingEdit] = useState(false)
  const [editError, setEditError] = useState('')

  // Delete confirmation modal state
  const [deletingScenario, setDeletingScenario] = useState(null)
  const [isDeleting, setIsDeleting] = useState(false)

  const showToast = (message, type = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 4500)
  }

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

  const handleToggleStatus = async (scenario) => {
    const newStatus = scenario.status === 'Published' ? 'Draft' : 'Published'
    try {
      await api.patch(`/admin/scenarios/${scenario.id}/status`, { status: newStatus })
      setScenarios((prev) =>
        prev.map((s) => (s.id === scenario.id ? { ...s, status: newStatus } : s))
      )
      loadAdminData()
      showToast(`Scenario marked as ${newStatus}!`)
    } catch (err) {
      showToast(`Failed to update status: ${err.message}`, 'error')
    }
  }

  const handleAddCreateQuestion = () => {
    setCreateQuestions([...createQuestions, { q: '', a: '', explanation: '', points: 10 }])
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

  // ATOMIC SCENARIO CREATION
  const handleCreateSubmit = async (e) => {
    e.preventDefault()
    setIsSubmitting(true)
    setCreateError('')
    setCreateSuccessData(null)

    try {
      setSubmitStep('Step 1/2: Atomically creating scenario, alert, Sigma rule, and questions...')
      const validQuestions = createQuestions
        .filter((q) => q.q.trim() && q.a.trim())
        .map((q) => ({
          question_text: q.q.trim(),
          correct_answer: q.a.trim(),
          explanation: q.explanation?.trim() || null,
          points: parseInt(q.points) || 10,
        }))

      const fullRes = await api.post('/admin/scenarios/full', {
        name: createName,
        description: createDesc,
        mitre_technique: createMitre,
        status: createStatus,
        alert_title: createAlertTitle || `Detection Alert: ${createName}`,
        alert_severity: createAlertSeverity,
        sigma_rule: createSigmaRule.trim() || null,
        questions: validQuestions,
      })

      const scId = fullRes.data.id
      const totalPts = validQuestions.reduce((acc, q) => acc + q.points, 0)

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

      setCreateSuccessData({
        id: scId,
        name: createName,
        status: createStatus,
        mitre: createMitre,
        alertTitle: createAlertTitle,
        questionsCount: validQuestions.length,
        totalPoints: totalPts,
        logsCount: logsInserted,
      })

      showToast(`Scenario "${createName}" (${totalPts} pts) created atomically!`)

      setCreateName('')
      setCreateDesc('')
      setCreateMitre('')
      setCreateAlertTitle('')
      setCreateAlertSeverity('High')
      setCreateSigmaRule('')
      setCreateQuestions([{ q: '', a: '', explanation: '', points: 10 }])
      setCreateFile(null)

      loadAdminData()
    } catch (err) {
      setCreateError(err.response?.data?.detail || err.message)
      showToast(`Creation failed: ${err.message}`, 'error')
    } finally {
      setIsSubmitting(false)
      setSubmitStep('')
    }
  }

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
      setEditSigmaRule(detail.alert?.sigma_rule || '')
      setEditQuestions(
        detail.questions && detail.questions.length > 0
          ? detail.questions.map((q) => ({
              question_text: q.question_text,
              correct_answer: q.correct_answer,
              explanation: q.explanation || '',
              points: q.points ?? 10,
            }))
          : [{ question_text: '', correct_answer: '', explanation: '', points: 10 }]
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
      const payload = {
        name: editName,
        description: editDesc,
        mitre_technique: editMitre,
        status: editStatus,
        alert_title: editAlertTitle,
        alert_severity: editAlertSeverity,
        sigma_rule: editSigmaRule.trim() || null,
        questions: editQuestions
          .filter((q) => q.question_text.trim() && q.correct_answer.trim())
          .map((q) => ({
            question_text: q.question_text,
            correct_answer: q.correct_answer,
            explanation: q.explanation?.trim() || null,
            points: parseInt(q.points) || 10,
          })),
      }
      await api.put(`/admin/scenarios/${editingScenario.id}/full`, payload)

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

  const filteredScenarios = scenarios.filter((s) => {
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
      {toast && (
        <div className={`admin-toast toast-${toast.type}`}>
          <span>{toast.message}</span>
          <button className="toast-close" onClick={() => setToast(null)}>×</button>
        </div>
      )}

      <div className="admin-header-strip">
        <div>
          <h2>
            <ShieldCheck size={22} style={{ verticalAlign: 'middle', marginRight: '8px' }} color="#00ffcc" />
            SOC Admin & Scenario Management
          </h2>
          <p className="admin-subtitle">
            Manage investigation training scenarios, Sigma rules, Windows Event logs, and trainee debrief explanations.
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
                Published ({scenarios.filter((s) => s.status === 'Published').length})
              </button>
              <button
                className={`filter-btn ${filterStatus === 'draft' ? 'active' : ''}`}
                onClick={() => setFilterStatus('draft')}
              >
                Drafts ({scenarios.filter((s) => s.status === 'Draft').length})
              </button>
            </div>
            <div className="search-wrap">
              <input
                type="text"
                placeholder="Search scenarios or MITRE ID..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                className="admin-search-input"
              />
            </div>
          </div>

          {loadingScenarios ? (
            <div className="loading">Loading scenarios...</div>
          ) : filteredScenarios.length === 0 ? (
            <div className="empty-scenarios-card">
              <p>No scenarios found matching your criteria.</p>
              <button className="btn btn-primary" onClick={() => setActiveTab('create')}>
                + Create a Scenario Now
              </button>
            </div>
          ) : (
            <div className="scenario-admin-grid">
              {filteredScenarios.map((sc) => (
                <div key={sc.id} className="scenario-admin-card">
                  <div className="sc-card-top">
                    <div className="sc-header-row">
                      <div className="sc-title-block">
                        <span className="sc-id-badge">#{sc.id}</span>
                        <h3>{sc.name}</h3>
                      </div>
                      <span className={`status-pill ${sc.status === 'Published' ? 'status-published' : 'status-draft'}`}>
                        {sc.status}
                      </span>
                    </div>
                    <div className="sc-badges-row">
                      <span className="mitre-badge">{sc.mitre_technique}</span>
                      {sc.alert && (
                        <span className={`severity-badge-sm severity-${sc.alert.severity?.toLowerCase()}`}>
                          {sc.alert.severity} Severity
                        </span>
                      )}
                      <span className="metric-chip">
                        <FileText size={13} style={{ verticalAlign: 'middle', marginRight: '4px' }} />
                        {sc.logs_count} Logs
                      </span>
                      <span className="metric-chip">
                        <HelpCircle size={13} style={{ verticalAlign: 'middle', marginRight: '4px' }} />
                        {sc.questions_count} Questions
                      </span>
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
                      className={`btn-action ${sc.status === 'Published' ? 'btn-unpublish' : 'btn-publish'}`}
                      onClick={() => handleToggleStatus(sc)}
                    >
                      {sc.status === 'Published' ? 'Set as Draft' : 'Publish Scenario'}
                    </button>
                    <button className="btn-action btn-edit" onClick={() => openEditModal(sc)}>
                      <Edit3 size={13} style={{ verticalAlign: 'middle', marginRight: '4px' }} />
                      Edit
                    </button>
                    <Link to={`/investigate/${sc.id}`} className="btn-action btn-preview">
                      Preview
                    </Link>
                    <button className="btn-action btn-delete" onClick={() => setDeletingScenario(sc)}>
                      <Trash2 size={13} style={{ verticalAlign: 'middle', marginRight: '4px' }} />
                      Delete
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'create' && (
        <div className="admin-form-panel">
          {createSuccessData && (
            <div className="scenario-creation-success-box">
              <div className="success-banner-header">
                <CheckCircle2 size={32} color="#4ade80" />
                <div>
                  <h3>Scenario "{createSuccessData.name}" Created Atomically!</h3>
                  <p>
                    {createSuccessData.questionsCount} questions ({createSuccessData.totalPoints} pts) •{' '}
                    {createSuccessData.logsCount} events ingested.
                  </p>
                </div>
              </div>
              <div className="success-actions-row">
                <Link to={`/investigate/${createSuccessData.id}`} className="btn btn-primary">
                  Launch Scenario →
                </Link>
                <button className="btn btn-secondary" onClick={() => setActiveTab('manage')}>
                  Back to Scenario Manager
                </button>
              </div>
            </div>
          )}

          {createError && <div className="admin-error-box">{createError}</div>}
          {isSubmitting && (
            <div className="submission-progress-box">
              <div className="spinner" />
              <span>{submitStep}</span>
            </div>
          )}

          <form onSubmit={handleCreateSubmit}>
            <div className="form-section-card">
              <div className="section-title">
                <span className="step-num">1</span>
                <h4>Scenario Metadata & MITRE Mapping</h4>
              </div>
              <div className="form-row">
                <div className="form-field flex-2">
                  <label>Scenario Name</label>
                  <input
                    className="admin-input"
                    value={createName}
                    onChange={(e) => setCreateName(e.target.value)}
                    placeholder="e.g., Golden Ticket Forgery"
                    required
                  />
                </div>
                <div className="form-field flex-1">
                  <label>MITRE Technique ID</label>
                  <input
                    className="admin-input"
                    value={createMitre}
                    onChange={(e) => setCreateMitre(e.target.value)}
                    placeholder="e.g., T1558.001"
                    required
                  />
                </div>
                <div className="form-field flex-1">
                  <label>Visibility Status</label>
                  <select
                    className="admin-input"
                    value={createStatus}
                    onChange={(e) => setCreateStatus(e.target.value)}
                  >
                    <option value="Published">Published</option>
                    <option value="Draft">Draft</option>
                  </select>
                </div>
              </div>
              <div className="form-field">
                <label>Briefing Description</label>
                <textarea
                  className="admin-input"
                  rows={3}
                  value={createDesc}
                  onChange={(e) => setCreateDesc(e.target.value)}
                  required
                />
              </div>
            </div>

            <div className="form-section-card">
              <div className="section-title">
                <span className="step-num">2</span>
                <h4>Triggered SIEM Alert & Static Sigma Detection Rule</h4>
              </div>
              <div className="form-row">
                <div className="form-field flex-3">
                  <label>Alert Title</label>
                  <input
                    className="admin-input"
                    value={createAlertTitle}
                    onChange={(e) => setCreateAlertTitle(e.target.value)}
                    placeholder="High Severity: Suspicious Kerberos Ticket Lifetime"
                    required
                  />
                </div>
                <div className="form-field flex-1">
                  <label>Severity</label>
                  <select
                    className="admin-input"
                    value={createAlertSeverity}
                    onChange={(e) => setCreateAlertSeverity(e.target.value)}
                  >
                    <option value="Low">Low</option>
                    <option value="Medium">Medium</option>
                    <option value="High">High</option>
                    <option value="Critical">Critical</option>
                  </select>
                </div>
              </div>
              <div className="form-field">
                <label>Sigma Detection Rule YAML (Optional — shown to trainees in workbench)</label>
                <textarea
                  className="admin-input"
                  rows={5}
                  style={{ fontFamily: 'monospace', fontSize: '0.82rem' }}
                  value={createSigmaRule}
                  onChange={(e) => setCreateSigmaRule(e.target.value)}
                  placeholder="title: Suspicious Activity&#10;detection:&#10;  selection:&#10;    EventID: 4624"
                />
              </div>
            </div>

            <div className="form-section-card">
              <div className="section-title">
                <span className="step-num">3</span>
                <h4>Investigation Questions & Debrief Explanations</h4>
              </div>
              {createQuestions.map((q, idx) => (
                <div key={idx} style={{ marginBottom: 14, paddingBottom: 12, borderBottom: '1px solid var(--border)' }}>
                  <div className="question-input-row">
                    <span className="q-index-pill">Q{idx + 1}</span>
                    <input
                      className="admin-input flex-2"
                      placeholder="Question prompt..."
                      value={q.q}
                      onChange={(e) => handleCreateQuestionChange(idx, 'q', e.target.value)}
                      required
                    />
                    <input
                      className="admin-input flex-1"
                      placeholder="Expected Answer..."
                      value={q.a}
                      onChange={(e) => handleCreateQuestionChange(idx, 'a', e.target.value)}
                      required
                    />
                    <input
                      type="number"
                      className="admin-input"
                      style={{ width: 80 }}
                      value={q.points}
                      onChange={(e) => handleCreateQuestionChange(idx, 'points', e.target.value)}
                    />
                    <button
                      type="button"
                      className="btn-remove-q"
                      onClick={() => handleRemoveCreateQuestion(idx)}
                    >
                      ×
                    </button>
                  </div>
                  <input
                    className="admin-input"
                    style={{ width: '100%', marginTop: 6 }}
                    placeholder="Debrief Explanation (shown after grading to explain how to find the IOC)..."
                    value={q.explanation}
                    onChange={(e) => handleCreateQuestionChange(idx, 'explanation', e.target.value)}
                  />
                </div>
              ))}
              <button type="button" className="btn btn-secondary btn-sm" onClick={handleAddCreateQuestion}>
                + Add Question
              </button>
            </div>

            <div className="form-section-card">
              <div className="section-title">
                <span className="step-num">4</span>
                <h4>Windows Event Log Dataset (.zip)</h4>
              </div>
              <div className="file-upload-zone">
                <input
                  type="file"
                  accept=".zip"
                  onChange={(e) => setCreateFile(e.target.files[0] || null)}
                />
                {createFile && <div className="selected-file-info">Selected: {createFile.name}</div>}
              </div>
            </div>

            <div className="form-actions-bar">
              <button type="submit" className="btn btn-primary btn-lg" disabled={isSubmitting}>
                {isSubmitting ? 'Creating Scenario...' : 'Create Scenario Atomically'}
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Edit Modal */}
      {editingScenario && (
        <div className="modal-backdrop">
          <div className="modal-card">
            <div className="modal-header">
              <h3>Edit Scenario #{editingScenario.id}</h3>
              <button className="modal-close-btn" onClick={() => setEditingScenario(null)}>×</button>
            </div>
            <form onSubmit={handleSaveEdit} className="modal-form">
              <div className="modal-scroll-area">
                {editError && <div className="admin-error-box">{editError}</div>}
                <div className="form-field">
                  <label>Scenario Name</label>
                  <input className="admin-input" value={editName} onChange={(e) => setEditName(e.target.value)} required />
                </div>
                <div className="form-row">
                  <div className="form-field flex-1">
                    <label>MITRE ID</label>
                    <input className="admin-input" value={editMitre} onChange={(e) => setEditMitre(e.target.value)} required />
                  </div>
                  <div className="form-field flex-1">
                    <label>Status</label>
                    <select className="admin-input" value={editStatus} onChange={(e) => setEditStatus(e.target.value)}>
                      <option value="Published">Published</option>
                      <option value="Draft">Draft</option>
                    </select>
                  </div>
                </div>
                <div className="form-field">
                  <label>Description</label>
                  <textarea className="admin-input" rows={3} value={editDesc} onChange={(e) => setEditDesc(e.target.value)} required />
                </div>
                <div className="form-row">
                  <div className="form-field flex-2">
                    <label>Alert Title</label>
                    <input className="admin-input" value={editAlertTitle} onChange={(e) => setEditAlertTitle(e.target.value)} />
                  </div>
                  <div className="form-field flex-1">
                    <label>Severity</label>
                    <select className="admin-input" value={editAlertSeverity} onChange={(e) => setEditAlertSeverity(e.target.value)}>
                      <option value="Low">Low</option>
                      <option value="Medium">Medium</option>
                      <option value="High">High</option>
                      <option value="Critical">Critical</option>
                    </select>
                  </div>
                </div>
                <div className="form-field">
                  <label>Sigma Rule (YAML)</label>
                  <textarea
                    className="admin-input"
                    rows={4}
                    style={{ fontFamily: 'monospace', fontSize: '0.8rem' }}
                    value={editSigmaRule}
                    onChange={(e) => setEditSigmaRule(e.target.value)}
                  />
                </div>
              </div>
              <div className="modal-footer">
                <button type="button" className="btn btn-secondary" onClick={() => setEditingScenario(null)}>
                  Cancel
                </button>
                <button type="submit" className="btn btn-primary" disabled={isSavingEdit}>
                  {isSavingEdit ? 'Saving...' : 'Save Changes'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}

      {/* Delete Confirmation Modal */}
      {deletingScenario && (
        <div className="modal-backdrop">
          <div className="modal-card modal-sm">
            <div className="modal-header">
              <h3>Confirm Deletion</h3>
              <button className="modal-close-btn" onClick={() => setDeletingScenario(null)}>×</button>
            </div>
            <div className="modal-body-padding">
              <p>Are you sure you want to permanently delete <strong>{deletingScenario.name}</strong> and all its logs?</p>
            </div>
            <div className="modal-footer">
              <button className="btn btn-secondary" onClick={() => setDeletingScenario(null)}>Cancel</button>
              <button className="btn btn-danger" onClick={handleDeleteScenario} disabled={isDeleting}>
                {isDeleting ? 'Deleting...' : 'Delete Permanently'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
