import { useEffect, useState } from 'react'
import { devicesApi } from '../api/devices'
import type { Device, ResolutionSummary } from '../types'

const RESOLUTION_LABEL: Record<string, string> = {
  snmp: 'Verified (SNMP)',
  syslog_reported: 'Self-reported',
  unresolved: 'Unresolved',
}

const PAGE_SIZE_OPTIONS = [10, 25, 50, 100, 500]
const AUTO_REFRESH_MS = 30000

function ResolutionBadge({ method }: { method: string }) {
  return <span className={`badge badge-${method}`}>{RESOLUTION_LABEL[method] ?? method}</span>
}

export function Devices() {
  const [devices, setDevices] = useState<Device[] | null>(null)
  const [hasMore, setHasMore] = useState(false)
  const [summary, setSummary] = useState<ResolutionSummary[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [pageSize, setPageSize] = useState(25)
  const [offset, setOffset] = useState(0)
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null)

  const load = (silent = false) => {
    if (!silent) setError(null)
    Promise.all([devicesApi.list(pageSize, offset), devicesApi.resolutionSummary()])
      .then(([deviceResp, summaryList]) => {
        setDevices(deviceResp.items)
        setHasMore(deviceResp.has_more)
        setSummary(summaryList)
        setLastUpdated(new Date())
      })
      .catch(() => setError('Could not load device data — is ClickHouse reachable from the API?'))
  }

  useEffect(() => {
    load()
  }, [pageSize, offset])

  // Auto-refresh the current page in the background, without resetting
  // pageSize/offset or flashing the table -- devices resolve and new ones
  // appear continuously, so this page shouldn't need a manual reload to
  // stay current.
  useEffect(() => {
    const interval = setInterval(() => load(true), AUTO_REFRESH_MS)
    return () => clearInterval(interval)
  }, [pageSize, offset])

  const totalDevices = summary?.reduce((sum, s) => sum + s.device_count, 0) ?? 0

  function changePageSize(size: number) {
    setPageSize(size)
    setOffset(0)
  }

  return (
    <div>
      <h2>Devices (last 24h)</h2>
      {lastUpdated && (
        <p className="page-hint">
          Auto-refreshes every 30s — last updated {lastUpdated.toLocaleTimeString()}.
        </p>
      )}

      {error && <p className="form-error">{error}</p>}

      {summary && (
        <div className="summary-row">
          {summary.map((s) => (
            <div key={s.resolution_method} className="summary-tile">
              <div className="summary-count">{s.device_count}</div>
              <div className="summary-label">{RESOLUTION_LABEL[s.resolution_method] ?? s.resolution_method}</div>
              <div className="summary-pct">
                {totalDevices ? Math.round((s.device_count / totalDevices) * 100) : 0}%
              </div>
            </div>
          ))}
        </div>
      )}

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
            <th>Hostname</th>
            <th>IP</th>
            <th>Vendor</th>
            <th>Identity</th>
            <th>Events (24h)</th>
            <th>Last seen</th>
          </tr>
        </thead>
        <tbody>
          {devices?.map((d) => (
            <tr key={d.ip}>
              <td>{d.hostname}</td>
              <td className="mono">{d.ip}</td>
              <td>
                {d.vendor}
                {d.vendor_source === 'passive' && (
                  <span className="vendor-hint" title="Guessed from the syslog message format, not SNMP-verified">
                    {' '}
                    (pattern-detected)
                  </span>
                )}
              </td>
              <td>
                <ResolutionBadge method={d.resolution_method} />
              </td>
              <td>{d.event_count.toLocaleString()}</td>
              <td>{new Date(d.last_seen).toLocaleString()}</td>
            </tr>
          ))}
          {devices?.length === 0 && (
            <tr>
              <td colSpan={6}>No devices seen in the last 24 hours.</td>
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
          Showing {devices?.length ? offset + 1 : 0}–{offset + (devices?.length ?? 0)}
        </span>
      </div>
    </div>
  )
}
