import { useEffect, useState } from 'react'
import { logsApi } from '../api/logs'
import type { LogEntry, LogSearchFilters } from '../types'

const SEVERITY_OPTIONS = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']

const PAGE_SIZE = 50

const EMPTY_FILTERS: LogSearchFilters = {}

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-severity-${severity}`}>{severity}</span>
}

export function Logs() {
  const [filters, setFilters] = useState<LogSearchFilters>(EMPTY_FILTERS)
  const [pendingFilters, setPendingFilters] = useState<LogSearchFilters>(EMPTY_FILTERS)
  const [offset, setOffset] = useState(0)
  const [items, setItems] = useState<LogEntry[] | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true)
    setError(null)
    logsApi
      .search({ ...filters, limit: PAGE_SIZE, offset })
      .then((res) => {
        setItems(res.items)
        setHasMore(res.has_more)
      })
      .catch(() => setError('Could not search logs — is ClickHouse reachable from the API?'))
      .finally(() => setLoading(false))
  }, [filters, offset])

  function applyFilters(e: React.FormEvent) {
    e.preventDefault()
    setOffset(0)
    setFilters(pendingFilters)
  }

  function clearFilters() {
    setPendingFilters(EMPTY_FILTERS)
    setOffset(0)
    setFilters(EMPTY_FILTERS)
  }

  function updateField(field: keyof LogSearchFilters, value: string) {
    setPendingFilters((prev) => ({ ...prev, [field]: value || undefined }))
  }

  return (
    <div>
      <h2>Log search</h2>
      <p className="page-hint">
        Searches the last 24 hours by default. Narrow the time range for faster results on a busy day.
      </p>

      <form className="credential-form" onSubmit={applyFilters}>
        <div className="form-grid">
          <label>
            Keyword (message contains)
            <input
              type="text"
              value={pendingFilters.q ?? ''}
              onChange={(e) => updateField('q', e.target.value)}
              placeholder="e.g. authentication failure"
            />
          </label>
          <label>
            Hostname
            <input type="text" value={pendingFilters.hostname ?? ''} onChange={(e) => updateField('hostname', e.target.value)} />
          </label>
          <label>
            Source IP
            <input type="text" value={pendingFilters.source_ip ?? ''} onChange={(e) => updateField('source_ip', e.target.value)} />
          </label>
          <label>
            Program
            <input type="text" value={pendingFilters.program ?? ''} onChange={(e) => updateField('program', e.target.value)} />
          </label>
          <label>
            Severity
            <select value={pendingFilters.severity ?? ''} onChange={(e) => updateField('severity', e.target.value)}>
              <option value="">Any</option>
              {SEVERITY_OPTIONS.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
          <label>
            Category
            <input
              type="text"
              value={pendingFilters.predicted_category ?? ''}
              onChange={(e) => updateField('predicted_category', e.target.value)}
              placeholder="e.g. AUTH, NETWORK"
            />
          </label>
          <label>
            Start
            <input type="datetime-local" value={pendingFilters.start ?? ''} onChange={(e) => updateField('start', e.target.value)} />
          </label>
          <label>
            End
            <input type="datetime-local" value={pendingFilters.end ?? ''} onChange={(e) => updateField('end', e.target.value)} />
          </label>
        </div>
        <div className="form-actions">
          <button type="submit">Search</button>
          <button type="button" onClick={clearFilters}>
            Clear
          </button>
        </div>
      </form>

      {error && <p className="form-error">{error}</p>}
      {loading && <p className="page-hint">Searching…</p>}

      <table className="data-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Hostname</th>
            <th>Source IP</th>
            <th>Severity</th>
            <th>Program</th>
            <th>Category</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {items?.map((entry, i) => (
            <tr key={`${entry.event_time}-${entry.source_ip}-${i}`}>
              <td className="mono">{new Date(entry.event_time).toLocaleString()}</td>
              <td>{entry.hostname}</td>
              <td className="mono">{entry.source_ip}</td>
              <td>
                <SeverityBadge severity={entry.severity} />
              </td>
              <td>{entry.program}</td>
              <td>{entry.predicted_category}</td>
              <td className="mono log-message">{entry.message}</td>
            </tr>
          ))}
          {items?.length === 0 && !loading && (
            <tr>
              <td colSpan={7}>No log entries match these filters.</td>
            </tr>
          )}
        </tbody>
      </table>

      <div className="form-actions" style={{ marginTop: 16 }}>
        <button type="button" disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - PAGE_SIZE))}>
          Previous
        </button>
        <button type="button" disabled={!hasMore} onClick={() => setOffset((o) => o + PAGE_SIZE)}>
          Next
        </button>
      </div>
    </div>
  )
}
