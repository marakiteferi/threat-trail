import { useState } from 'react'
import { Shield, Code, User, Globe, Copy, Check, AlertTriangle, Cpu, FileText } from 'lucide-react'

const EVENT_DESCRIPTIONS = {
  4625: 'Failed Logon — An account failed to authenticate',
  4624: 'Successful Logon — An account was successfully authenticated',
  4672: 'Special Privileges Assigned — Administrative logon detected',
  4688: 'Process Creation — A new executable or command was spawned',
  4689: 'Process Termination — An executable exited',
  1102: 'Audit Log Cleared — Security log was intentionally wiped',
  4720: 'User Account Created — New user added to domain or local machine',
  4726: 'User Account Deleted — Account removed',
  4738: 'User Account Modified — Attributes or permissions altered',
  1: 'Sysmon Event 1: Process Creation',
  3: 'Sysmon Event 3: Network Connection',
  10: 'Sysmon Event 10: Process Access (LSASS / Memory dumping attempt)',
  11: 'Sysmon Event 11: File Create',
  12: 'Sysmon Event 12: Registry Event (Object create/delete)',
  13: 'Sysmon Event 13: Registry Value Set',
}

const LOGON_TYPES = {
  '2': 'Type 2: Interactive (Console / Keyboard logon)',
  '3': 'Type 3: Network (SMB / RPC / Network Share / PsExec)',
  '4': 'Type 4: Batch (Scheduled task)',
  '5': 'Type 5: Service (Windows Service startup)',
  '7': 'Type 7: Unlock (Workstation unlocked)',
  '8': 'Type 8: NetworkCleartext (Basic authentication)',
  '9': 'Type 9: NewCredentials (RunAs with /netonly)',
  '10': 'Type 10: RemoteInteractive (RDP / Remote Desktop)',
  '11': 'Type 11: CachedInteractive (Offline logon)',
}

const STATUS_CODES = {
  '0xC000006D': 'STATUS_LOGON_FAILURE (Invalid credentials)',
  '0xC000006A': 'STATUS_PASSWORD_MUST_CHANGE / Bad Password',
  '0xC0000234': 'STATUS_ACCOUNT_LOCKED_OUT',
  '0xC0000072': 'STATUS_ACCOUNT_DISABLED',
  '0xC000006E': 'STATUS_ACCOUNT_RESTRICTION',
  '0xC0000071': 'STATUS_PASSWORD_EXPIRED',
  '0xC0000064': 'STATUS_NO_SUCH_USER',
}

function extractFromText(text, pattern) {
  if (!text || typeof text !== 'string') return null
  const match = text.match(pattern)
  if (match && match[1]) {
    const val = match[1].trim()
    return val && val !== '-' ? val : null
  }
  return null
}

export default function LogInspector({ log }) {
  const [activeTab, setActiveTab] = useState('parsed') // 'parsed' | 'raw'
  const [copied, setCopied] = useState(false)
  const [ipCopied, setIpCopied] = useState(false)

  const raw = log.raw_event_data || {}
  const msg = raw.Message || ''

  // Extracted fields prioritizing raw JSON keys, falling back to parsed Message text
  const eventId = log.event_id || raw.EventID || 0
  const eventDesc = EVENT_DESCRIPTIONS[eventId] || `Windows Event ${eventId}`

  const targetUser =
    log.username ||
    raw.TargetUserName ||
    raw.AccountName ||
    raw.SubjectUserName ||
    raw.TargetUser ||
    extractFromText(msg, /Account Name:\s*([^\r\n\t]+)/) ||
    extractFromText(msg, /Account For Which Logon Failed:[\s\S]*?Account Name:\s*([^\r\n\t]+)/) ||
    '-'

  const targetDomain =
    raw.TargetDomainName ||
    raw.AccountDomain ||
    raw.SubjectDomainName ||
    raw.Domain ||
    extractFromText(msg, /Account Domain:\s*([^\r\n\t]+)/) ||
    '-'

  const sourceIp =
    log.source_ip ||
    raw.SourceAddress ||
    raw.IpAddress ||
    raw.SourceIp ||
    extractFromText(msg, /Source Network Address:\s*([^\r\n\t]+)/) ||
    extractFromText(msg, /Source Address:\s*([^\r\n\t]+)/) ||
    '-'

  const sourcePort =
    raw.SourcePort ||
    raw.port ||
    extractFromText(msg, /Source Port:\s*([^\r\n\t]+)/) ||
    '-'

  const workstation =
    log.target_host ||
    raw.Hostname ||
    raw.Computer ||
    raw.WorkstationName ||
    raw.host ||
    extractFromText(msg, /Workstation Name:\s*([^\r\n\t]+)/) ||
    '-'

  const logonTypeRaw =
    raw.LogonType ||
    extractFromText(msg, /Logon Type:\s*([0-9]+)/)

  const logonTypeDesc = logonTypeRaw ? (LOGON_TYPES[String(logonTypeRaw)] || `Type ${logonTypeRaw}`) : null

  const failureReason =
    raw.FailureReason ||
    extractFromText(msg, /Failure Reason:\s*([^\r\n\t]+)/)

  const statusCode =
    raw.Status ||
    extractFromText(msg, /Status:\s*(0x[0-9a-fA-F]+)/)

  const subStatusCode =
    raw.SubStatus ||
    extractFromText(msg, /Sub Status:\s*(0x[0-9a-fA-F]+)/)

  const processName =
    raw.SourceImage ||
    raw.TargetImage ||
    raw.Application ||
    raw.ProcessName ||
    extractFromText(msg, /Application Name:\s*([^\r\n\t]+)/) ||
    extractFromText(msg, /Process Name:\s*([^\r\n\t]+)/)

  const processId =
    raw.ProcessId ||
    raw.ExecutionProcessID ||
    raw.SourceProcessId ||
    extractFromText(msg, /Process ID:\s*([^\r\n\t]+)/)

  const logonProcess =
    raw.LogonProcessName ||
    extractFromText(msg, /Logon Process:\s*([^\r\n\t]+)/)

  const authPackage =
    raw.AuthenticationPackageName ||
    extractFromText(msg, /Authentication Package:\s*([^\r\n\t]+)/)

  const handleCopyJson = () => {
    navigator.clipboard.writeText(JSON.stringify(raw, null, 2))
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const handleCopyIp = (ip) => {
    if (!ip || ip === '-') return
    navigator.clipboard.writeText(ip)
    setIpCopied(true)
    setTimeout(() => setIpCopied(false), 2000)
  }

  return (
    <div className="log-inspector">
      {/* Inspector Top Bar */}
      <div className="inspector-header">
        <div className="inspector-title">
          <span className={`inspector-badge ${eventId === 4624 ? 'badge-success' : 'badge-danger'}`}>
            ID {eventId}
          </span>
          <strong>{eventDesc}</strong>
        </div>

        <div className="inspector-tabs">
          <button
            type="button"
            className={`inspector-tab-btn ${activeTab === 'parsed' ? 'active' : ''}`}
            onClick={() => setActiveTab('parsed')}
          >
            <Shield size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
            SOC Fields
          </button>
          <button
            type="button"
            className={`inspector-tab-btn ${activeTab === 'raw' ? 'active' : ''}`}
            onClick={() => setActiveTab('raw')}
          >
            <Code size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
            Raw JSON
          </button>
        </div>
      </div>

      {/* Tab 1: Parsed SOC Fields */}
      {activeTab === 'parsed' && (
        <div className="inspector-content">
          <div className="inspector-grid">
            {/* Account & Authentication */}
            <div className="inspector-card">
              <h4>
                <User size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
                Account & Authentication
              </h4>
              <div className="card-row">
                <span className="field-label">Target User:</span>
                <span className="field-value highlight">{targetUser}</span>
              </div>
              <div className="card-row">
                <span className="field-label">Domain:</span>
                <span className="field-value">{targetDomain}</span>
              </div>
              {logonTypeDesc && (
                <div className="card-row">
                  <span className="field-label">Logon Type:</span>
                  <span className="field-value accent">{logonTypeDesc}</span>
                </div>
              )}
              {authPackage && (
                <div className="card-row">
                  <span className="field-label">Auth Package:</span>
                  <span className="field-value">{authPackage}</span>
                </div>
              )}
              {logonProcess && (
                <div className="card-row">
                  <span className="field-label">Logon Process:</span>
                  <span className="field-value">{logonProcess}</span>
                </div>
              )}
            </div>

            {/* Network & Source */}
            <div className="inspector-card">
              <h4>
                <Globe size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
                Source & Host
              </h4>
              <div className="card-row">
                <span className="field-label">Source IP:</span>
                <span className="field-value highlight">
                  {sourceIp}
                  {sourceIp !== '-' && (
                    <button
                      type="button"
                      className="copy-chip-btn"
                      onClick={() => handleCopyIp(sourceIp)}
                      title="Copy IP Address"
                    >
                      {ipCopied ? (
                        <><Check size={11} style={{ display: 'inline', marginRight: 3, verticalAlign: 'middle' }} /> Copied</>
                      ) : (
                        <><Copy size={11} style={{ display: 'inline', marginRight: 3, verticalAlign: 'middle' }} /> Copy</>
                      )}
                    </button>
                  )}
                </span>
              </div>
              <div className="card-row">
                <span className="field-label">Source Port:</span>
                <span className="field-value">{sourcePort}</span>
              </div>
              <div className="card-row">
                <span className="field-label">Workstation / Host:</span>
                <span className="field-value">{workstation}</span>
              </div>
              <div className="card-row">
                <span className="field-label">Timestamp:</span>
                <span className="field-value text-dim">{new Date(log.timestamp).toLocaleString()}</span>
              </div>
            </div>

            {/* Failure / Security Analysis (if present) */}
            {(failureReason || statusCode || subStatusCode) && (
              <div className="inspector-card failure-card">
                <h4>
                  <AlertTriangle size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
                  Security Status & Failure Info
                </h4>
                {failureReason && (
                  <div className="card-row">
                    <span className="field-label">Failure Reason:</span>
                    <span className="field-value text-danger">{failureReason}</span>
                  </div>
                )}
                {statusCode && (
                  <div className="card-row">
                    <span className="field-label">Status:</span>
                    <span className="field-value code-pill">
                      {statusCode} {STATUS_CODES[statusCode] ? `(${STATUS_CODES[statusCode]})` : ''}
                    </span>
                  </div>
                )}
                {subStatusCode && (
                  <div className="card-row">
                    <span className="field-label">Sub Status:</span>
                    <span className="field-value code-pill">
                      {subStatusCode} {STATUS_CODES[subStatusCode] ? `(${STATUS_CODES[subStatusCode]})` : ''}
                    </span>
                  </div>
                )}
              </div>
            )}

            {/* Process / Sysmon Details (if present) */}
            {(processName || processId || raw.GrantedAccess || raw.CallTrace) && (
              <div className="inspector-card">
                <h4>
                  <Cpu size={14} style={{ display: 'inline', marginRight: 6, verticalAlign: 'middle' }} />
                  Process & Execution
                </h4>
                {processName && (
                  <div className="card-row">
                    <span className="field-label">Process Image:</span>
                    <span className="field-value code-pill break-all">{processName}</span>
                  </div>
                )}
                {processId && (
                  <div className="card-row">
                    <span className="field-label">Process ID:</span>
                    <span className="field-value">{processId}</span>
                  </div>
                )}
                {raw.GrantedAccess && (
                  <div className="card-row">
                    <span className="field-label">Granted Access:</span>
                    <span className="field-value code-pill">{raw.GrantedAccess}</span>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Clean Message block if available */}
          {msg && (
            <div className="inspector-message">
              <h5>
                <FileText size={13} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} />
                Event Log Message
              </h5>
              <div className="message-box">{msg}</div>
            </div>
          )}
        </div>
      )}

      {/* Tab 2: Raw JSON View */}
      {activeTab === 'raw' && (
        <div className="inspector-raw-container">
          <div className="raw-actions">
            <span className="text-dim">Raw Windows Event JSON payload</span>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={handleCopyJson}
            >
              {copied ? (
                <><Check size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} /> Copied to Clipboard!</>
              ) : (
                <><Copy size={12} style={{ display: 'inline', marginRight: 4, verticalAlign: 'middle' }} /> Copy JSON</>
              )}
            </button>
          </div>
          <pre className="raw-event-code">
            {JSON.stringify(raw, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}
