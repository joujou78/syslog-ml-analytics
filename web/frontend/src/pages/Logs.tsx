import { useEffect, useState } from 'react'
import { logsApi } from '../api/logs'
import type { LogEntry, LogSearchFilters } from '../types'
import { formatBeirutDateTime, formatBeirutTime } from '../utils/time'

const SEVERITY_OPTIONS = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100, 500]

// Milliseconds; 0 means "off". Off by default -- unlike Devices' fixed
// 30s auto-refresh, this page is also where you sit reading through a
// specific search/page of results, so silently re-fetching underneath
// someone mid-review should be something they opt into, not a default.
const AUTO_REFRESH_OPTIONS: { label: string; value: number }[] = [
  { label: 'Off', value: 0 },
  { label: '5s', value: 5000 },
  { label: '15s', value: 15000 },
  { label: '30s', value: 30000 },
  { label: '60s', value: 60000 },
]

const EMPTY_FILTERS: LogSearchFilters = {}

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-severity-${severity}`}>{severity}</span>
}

export function Logs() {
  const [filters, setFilters] = useState<LogSearchFilters>(EMPTY_FILTERS)
  const [pendingFilters, setPendingFilters] = useState<LogSearchFilters>(EMPTY_FILTERS)
  const [pageSize, setPageSize] = useState(50)
  const [offset, setOffset] = useState(0)
  const [items, setItems] = useState<LogEntry[] | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [autoRefreshMs, setAutoRefreshMs] = useState(0)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const load = (silent = false) => {
    if (!silent) {
      setLoading(true)
      setError(null)
    }
    logsApi
      .search({ ...filters, limit: pageSize, offset })
      .then((res) => {
        setItems(res.items)
        setHasMore(res.has_more)
        setLastUpdated(new Date())
      })
      .catch(() => setError('Could not search logs — is ClickHouse reachable from the API?'))
      .finally(() => {
        if (!silent) setLoading(false)
      })
  }

  useEffect(() => {
    load()
  }, [filters, pageSize, offset])

  // Auto-refresh the current search/page in the background when enabled --
  // doesn't touch filters/offset, so paging or editing the form is
  // unaffected. Off by default (see AUTO_REFRESH_OPTIONS above).
  useEffect(() => {
    if (!autoRefreshMs) return
    const interval = setInterval(() => load(true), autoRefreshMs)
    return () => clearInterval(interval)
  }, [autoRefreshMs, filters, pageSize, offset])

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

  function toggleOnlyAnomalies(checked: boolean) {
    setPendingFilters((prev) => ({ ...prev, only_anomalies: checked || undefined }))
  }

  function changePageSize(size: number) {
    setPageSize(size)
    setOffset(0)
  }

  function exportLogs(format: 'csv' | 'xml') {
    setExporting(true)
    setError(null)
    logsApi
      .export(filters, format)
      .then(({ truncated }) => {
        if (truncated) setError('Export was capped at 50,000 rows — narrow the time range to get everything.')
      })
      .catch(() => setError('Could not export logs — is ClickHouse reachable from the API?'))
      .finally(() => setExporting(false))
  }

  return (
    <div>
      <h2>Log search</h2>
      <p className="page-hint">
        Searches the last 24 hours by default. Narrow the time range for faster results on a busy day.
        Times shown are Beirut local time.
        {autoRefreshMs > 0 && lastUpdated && <> Auto-refreshing every {autoRefreshMs / 1000}s — last updated {formatBeirutTime(lastUpdated)}.</>}
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
          <label>
            Anomalies only
            <select
              value={pendingFilters.only_anomalies ? 'true' : 'false'}
              onChange={(e) => toggleOnlyAnomalies(e.target.value === 'true')}
            >
              <option value="false">No — show everything</option>
              <option value="true">Yes — only flagged events</option>
            </select>
          </label>
        </div>
        <div className="form-actions">
          <button type="submit">Search</button>
          <button type="button" onClick={clearFilters}>
            Clear
          </button>
          <button type="button" disabled={exporting} onClick={() => exportLogs('csv')}>
            {exporting ? 'Exporting…' : 'Export CSV'}
          </button>
          <button type="button" disabled={exporting} onClick={() => exportLogs('xml')}>
            {exporting ? 'Exporting…' : 'Export XML'}
          </button>
        </div>
      </form>

      {error && <p className="form-error">{error}</p>}
      {loading && <p className="page-hint">Searching…</p>}

      <div className="form-actions" style={{ alignItems: 'center' }}>
        <label style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
          Per page
          <select value={pageSize} onChange={(e) => changePageSize(Number(e.target.value))}>
            {PAGE_SIZE_OPTIONS.map((size) => (
              <option key={size} value={size}>
                {size}
              </option>
            ))}
          </select>
        </label>
        <label style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
          Auto-refresh
          <select value={autoRefreshMs} onChange={(e) => setAutoRefreshMs(Number(e.target.value))}>
            {AUTO_REFRESH_OPTIONS.map((opt) => (
              <option key={opt.value} value={opt.value}>
                {opt.label}
              </option>
            ))}
          </select>
        </label>
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th>Time</th>
            <th>Hostname</th>
            <th>Source IP</th>
            <th>Severity</th>
            <th>Program</th>
            <th>Category</th>
            <th>Anomaly</th>
            <th>Message</th>
          </tr>
        </thead>
        <tbody>
          {items?.map((entry, i) => (
            <tr key={`${entry.event_time}-${entry.source_ip}-${i}`}>
              <td className="mono">{formatBeirutDateTime(entry.event_time)}</td>
              <td>{entry.hostname}</td>
              <td className="mono">{entry.source_ip}</td>
              <td>
                <SeverityBadge severity={entry.severity} />
              </td>
              <td>{entry.program}</td>
              <td>{entry.predicted_category}</td>
              <td>
                {entry.anomaly_reasons.map((reason) => (
                  <span key={reason} className="badge badge-anomaly" title={reason}>
                    {reason.replace('_', ' ')}
                  </span>
                ))}
              </td>
              <td className="mono log-message">{entry.message}</td>
            </tr>
          ))}
          {items?.length === 0 && !loading && (
            <tr>
              <td colSpan={8}>No log entries match these filters.</td>
            </tr>
          )}
        </tbody>
      </table>

      <div className="form-actions" style={{ marginTop: 16 }}>
        <button type="button" disabled={offset === 0} onClick={() => setOffset((o) => Math.max(0, o - pageSize))}>
          Previous
        </button>
        <button type="button" disabled={!hasMore} onClick={() => setOffset((o) => o + pageSize)}>
          Next
        </button>
        <span className="page-hint">
          Showing {items?.length ? offset + 1 : 0}–{offset + (items?.length ?? 0)}
        </span>
      </div>
    </div>
  )
}
