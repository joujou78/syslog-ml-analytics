import { useEffect, useMemo, useState } from 'react'
import { Link } from 'react-router-dom'
import { anomalyWindowsApi } from '../api/anomalyWindows'
import type { AnomalyWindow, AnomalyWindowFilters } from '../types'
import { formatBeirutDateTime, fromDatetimeLocalBeirut, padWindow, toDatetimeLocalBeirut } from '../utils/time'

// +/- padding around the flagged 5-minute window itself -- an LLM asked
// about one bare window has nothing to reason over; the surrounding
// context is what lets it say what else was going on around the shift.
function explainLink(w: AnomalyWindow) {
  const { start, end } = padWindow(w.window_start, 10, 15)
  const params = new URLSearchParams({
    source_ip: w.source_ip,
    start,
    end,
    question:
      `${w.hostname}'s mix of log message types was flagged as unusual around this time ` +
      `(score ${w.anomaly_score.toFixed(3)}, scored against its ${w.model_scope} model). ` +
      'What was happening in its logs that might explain the shift?',
  })
  return `/log-assistant?${params.toString()}`
}

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100, 500]
const EMPTY_FILTERS: AnomalyWindowFilters = { only_anomalies: true }

type WindowSortKey = 'windowStart' | 'hostname' | 'sourceIp' | 'vendor' | 'model' | 'score' | 'eventCount'
type SortDir = 'asc' | 'desc'

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
  // Sorts only the currently-loaded page -- the server still decides
  // which rows make up "page 2" etc. (ordered by window_start, see
  // anomaly_window_service.py), this just lets you reorder what's
  // already on screen without changing what Next/Previous fetch.
  const [sort, setSort] = useState<{ key: WindowSortKey; dir: SortDir } | null>(null)

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

  const sortedItems = useMemo(() => {
    if (!items || !sort) return items
    const { key, dir } = sort
    const sign = dir === 'asc' ? 1 : -1
    const valueOf = (w: AnomalyWindow) => {
      switch (key) {
        case 'windowStart':
          return new Date(w.window_start).getTime()
        case 'hostname':
          return w.hostname.toLowerCase()
        case 'sourceIp':
          return w.source_ip
        case 'vendor':
          return w.vendor.toLowerCase()
        case 'model':
          return w.model_scope
        case 'score':
          return w.anomaly_score
        case 'eventCount':
          return w.event_count
      }
    }
    return [...items].sort((a, b) => {
      const av = valueOf(a)
      const bv = valueOf(b)
      if (av < bv) return -1 * sign
      if (av > bv) return 1 * sign
      return 0
    })
  }, [items, sort])

  function toggleSort(key: WindowSortKey) {
    setSort((prev) => {
      if (prev?.key !== key) return { key, dir: 'asc' }
      return { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
    })
  }

  function sortIndicator(key: WindowSortKey) {
    if (sort?.key !== key) return null
    return <span className="sort-arrow">{sort.dir === 'asc' ? ' ▲' : ' ▼'}</span>
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
            Start (Beirut time)
            <input
              type="datetime-local"
              value={pendingFilters.start ? toDatetimeLocalBeirut(pendingFilters.start) : ''}
              onChange={(e) => updateField('start', e.target.value ? fromDatetimeLocalBeirut(e.target.value) : '')}
            />
          </label>
          <label>
            End (Beirut time)
            <input
              type="datetime-local"
              value={pendingFilters.end ? toDatetimeLocalBeirut(pendingFilters.end) : ''}
              onChange={(e) => updateField('end', e.target.value ? fromDatetimeLocalBeirut(e.target.value) : '')}
            />
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
            <th className="sortable" onClick={() => toggleSort('windowStart')}>
              Window start{sortIndicator('windowStart')}
            </th>
            <th className="sortable" onClick={() => toggleSort('hostname')}>
              Hostname{sortIndicator('hostname')}
            </th>
            <th className="sortable" onClick={() => toggleSort('sourceIp')}>
              Source IP{sortIndicator('sourceIp')}
            </th>
            <th className="sortable" onClick={() => toggleSort('vendor')}>
              Vendor{sortIndicator('vendor')}
            </th>
            <th className="sortable" onClick={() => toggleSort('model')}>
              Model{sortIndicator('model')}
            </th>
            <th className="sortable" onClick={() => toggleSort('score')}>
              Score{sortIndicator('score')}
            </th>
            <th className="sortable" onClick={() => toggleSort('eventCount')}>
              Events in window{sortIndicator('eventCount')}
            </th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {sortedItems?.map((w, i) => (
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
              <td>
                <Link to={explainLink(w)}>Explain with AI</Link>
              </td>
            </tr>
          ))}
          {items?.length === 0 && !loading && (
            <tr>
              <td colSpan={8}>No anomaly windows match these filters.</td>
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
