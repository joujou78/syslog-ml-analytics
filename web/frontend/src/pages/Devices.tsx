import { useEffect, useState } from 'react'
import { devicesApi } from '../api/devices'
import type { Device, ResolutionSummary } from '../types'

const RESOLUTION_LABEL: Record<string, string> = {
  snmp: 'Verified (SNMP)',
  syslog_reported: 'Self-reported',
  unresolved: 'Unresolved',
}

function ResolutionBadge({ method }: { method: string }) {
  return <span className={`badge badge-${method}`}>{RESOLUTION_LABEL[method] ?? method}</span>
}

export function Devices() {
  const [devices, setDevices] = useState<Device[] | null>(null)
  const [summary, setSummary] = useState<ResolutionSummary[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    Promise.all([devicesApi.list(), devicesApi.resolutionSummary()])
      .then(([deviceList, summaryList]) => {
        setDevices(deviceList)
        setSummary(summaryList)
      })
      .catch(() => setError('Could not load device data — is ClickHouse reachable from the API?'))
  }, [])

  const totalDevices = summary?.reduce((sum, s) => sum + s.device_count, 0) ?? 0

  return (
    <div>
      <h2>Devices (last 24h)</h2>

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
    </div>
  )
}
