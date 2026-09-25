import { useEffect, useState } from 'react'
import { auditApi } from '../api/audit'
import type { AuditLogEntry } from '../types'
import { extractErrorMessage } from '../utils/errors'
import { formatBeirutDateTime } from '../utils/time'

export function AuditLog() {
  const [entries, setEntries] = useState<AuditLogEntry[] | null>(null)
  const [actions, setActions] = useState<string[]>([])
  const [actionFilter, setActionFilter] = useState('')
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    auditApi
      .actions()
      .then(setActions)
      .catch(() => setError('Could not load the action filter list'))
  }, [])

  useEffect(() => {
    // Guards against a slower earlier request (e.g. filter A) resolving
    // after a faster later one (filter B) and overwriting the table with
    // stale rows that no longer match the dropdown's current selection.
    let cancelled = false
    setError(null)
    auditApi
      .list({ action: actionFilter || undefined })
      .then((rows) => {
        if (!cancelled) setEntries(rows)
      })
      .catch((err) => {
        if (!cancelled) setError(extractErrorMessage(err, 'Could not load the audit log'))
      })
    return () => {
      cancelled = true
    }
  }, [actionFilter])

  return (
    <div>
      <h2>Audit Log</h2>
      <p className="page-hint">
        Every administrative change recorded across the system: alert rules, SNMP credentials, relay source IPs,
        anomaly acknowledgments, and query console usage. This is a read-only record — nothing here can be edited
        or deleted.
      </p>

      <label style={{ maxWidth: 280 }}>
        Filter by action
        <select value={actionFilter} onChange={(e) => setActionFilter(e.target.value)}>
          <option value="">All actions</option>
          {actions.map((a) => (
            <option key={a} value={a}>
              {a}
            </option>
          ))}
        </select>
      </label>

      {error && <p className="form-error">{error}</p>}

      <table className="data-table">
        <thead>
          <tr>
            <th>When</th>
            <th>Actor</th>
            <th>Action</th>
            <th>Target</th>
          </tr>
        </thead>
        <tbody>
          {entries?.map((e) => (
            <tr key={e.id}>
              <td className="mono">{formatBeirutDateTime(e.created_at)}</td>
              <td>{e.actor_username ?? <span className="vendor-hint">system</span>}</td>
              <td className="mono">{e.action}</td>
              <td className="mono">{e.target}</td>
            </tr>
          ))}
          {entries?.length === 0 && (
            <tr>
              <td colSpan={4}>No audit entries{actionFilter ? ' for this action' : ''} yet.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
