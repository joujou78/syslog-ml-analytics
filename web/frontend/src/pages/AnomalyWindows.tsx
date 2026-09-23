import { useEffect, useState } from 'react'
import { anomalyWindowsApi } from '../api/anomalyWindows'
import type { AnomalyWindow, AnomalyWindowFilters } from '../types'
import { formatBeirutDateTime } from '../utils/time'

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100, 500]
const EMPTY_FILTERS: AnomalyWindowFilters = { only_anomalies: true }

const SCOPE_LABEL: Record<string, string> = {
  device: 'Device-specific',
  vendor: 'Vendor baseline',
}

function ScopeBadge({ scope }: { scope: string }) {
  return <span className={`badge badge-scope-${scope}`}>{SCOPE_LABEL[scope] ?? scope}</span>
}

export function AnomalyWindows() {
  const [filters, setFilters] = useState<AnomalyWindowFilters>(EMPTY_FILTERS)
  const [pendingFilters, setPendingFilters] = useState<AnomalyWindowFilters>(EMPTY_FILTERS)
  const [pageSize, setPageSize] = useState(50)
  const [offset, setOffset] = useState(0)
  const [items, setItems] = useState<AnomalyWindow[] | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  useEffect(() => {
    setLoading(true)
    setError(null)
    anomalyWindowsApi
      .list(filters, pageSize, offset)
      .then((res) => {
        setItems(res.items)
        setHasMore(res.has_more)
      })
      .catch(() => setError('Could not load anomaly windows — is ClickHouse reachable from the API?'))
      .finally(() => setLoading(false))
  }, [filters, pageSize, offset])

  function updateField(field: keyof AnomalyWindowFilters, value: string) {
    setPendingFilters((prev) => ({ ...prev, [field]: value || undefined }))
  }

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

  function changePageSize(size: number) {
    setPageSize(size)
    setOffset(0)
  }

  return (
    <div>
      <h2>Anomaly windows</h2>
      <p className="page-hint">
        Flags a shift in a device's <em>mix</em> of log message types over a 5-minute window — a different signal
        from Log Search's per-event anomalies, since it can catch a device suddenly logging an unusual combination
        of things even when no single message looks abnormal on its own. Scored periodically, not in real time, so
        a newly-anomalous window can take a few minutes to appear. "Vendor baseline" means the device doesn't have
        enough history of its own yet, so it's compared against other devices of the same vendor instead. Times
        shown are Beirut local time.
      </p>

      <form className="credential-form" onSubmit={applyFilters}>
        <div className="form-grid">
          <label>
            Source IP
            <input
              type="text"
              value={pendingFilters.source_ip ?? ''}
              onChange={(e) => updateField('source_ip', e.target.value)}
            />
          </label>
          <label>
            Vendor
            <input type="text" value={pendingFilters.vendor ?? ''} onChange={(e) => updateField('vendor', e.target.value)} />
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
            Show
            <select
              value={pendingFilters.only_anomalies === false ? 'all' : 'anomalies'}
              onChange={(e) =>
                setPendingFilters((prev) => ({ ...prev, only_anomalies: e.target.value === 'anomalies' }))
              }
            >
              <option value="anomalies">Flagged windows only</option>
              <option value="all">All scored windows</option>
            </select>
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
      {loading && <p className="page-hint">Loading…</p>}

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
      </div>

      <table className="data-table">
        <thead>
          <tr>
            <th>Window start</th>
            <th>Hostname</th>
            <th>Source IP</th>
            <th>Vendor</th>
            <th>Model</th>
            <th>Score</th>
            <th>Events in window</th>
          </tr>
        </thead>
        <tbody>
          {items?.map((w, i) => (
            <tr key={`${w.source_ip}-${w.window_start}-${i}`}>
              <td className="mono">{formatBeirutDateTime(w.window_start)}</td>
              <td>{w.hostname}</td>
              <td className="mono">{w.source_ip}</td>
              <td>{w.vendor}</td>
              <td>
                <ScopeBadge scope={w.model_scope} />
              </td>
              <td className="mono">{w.anomaly_score.toFixed(3)}</td>
              <td>{w.event_count.toLocaleString()}</td>
            </tr>
          ))}
          {items?.length === 0 && !loading && (
            <tr>
              <td colSpan={7}>No anomaly windows match these filters.</td>
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
