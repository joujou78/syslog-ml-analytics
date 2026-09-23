import { useEffect, useState } from 'react'
import { anomalySummaryApi } from '../api/anomalySummary'
import { useAuth } from '../auth/AuthContext'
import type { DeviceAnomalySummaryRow, VendorAnomalySummaryRow } from '../types'
import { extractErrorMessage } from '../utils/errors'
import { formatBeirutDateTime } from '../utils/time'

type View = 'device' | 'vendor'

function rowKey(sourceIp: string, reason: string) {
  return `${sourceIp}::${reason}`
}

export function AnomalySummary() {
  const { user } = useAuth()
  const canManage = user?.role === 'admin' || user?.role === 'analyst'

  const [view, setView] = useState<View>('device')
  const [deviceRows, setDeviceRows] = useState<DeviceAnomalySummaryRow[] | null>(null)
  const [vendorRows, setVendorRows] = useState<VendorAnomalySummaryRow[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [noteDrafts, setNoteDrafts] = useState<Record<string, string>>({})
  const [busyRow, setBusyRow] = useState<string | null>(null)

  const load = () => {
    setLoading(true)
    setError(null)
    const request = view === 'device' ? anomalySummaryApi.devices().then(setDeviceRows) : anomalySummaryApi.vendors().then(setVendorRows)
    request
      .catch(() => setError('Could not load anomaly summary — is ClickHouse reachable from the API?'))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view])

  async function handleAcknowledge(row: DeviceAnomalySummaryRow) {
    const key = rowKey(row.source_ip, row.anomaly_reason)
    setBusyRow(key)
    setError(null)
    try {
      await anomalySummaryApi.acknowledge(row.source_ip, row.anomaly_reason, noteDrafts[key])
      setNoteDrafts((prev) => ({ ...prev, [key]: '' }))
      load()
    } catch (err) {
      setError(extractErrorMessage(err, 'Could not acknowledge this'))
    } finally {
      setBusyRow(null)
    }
  }

  async function handleUnacknowledge(row: DeviceAnomalySummaryRow) {
    if (!confirm(`Un-acknowledge ${row.anomaly_reason} on ${row.hostname}? It will show as unhandled again.`)) return
    const key = rowKey(row.source_ip, row.anomaly_reason)
    setBusyRow(key)
    setError(null)
    try {
      await anomalySummaryApi.unacknowledge(row.source_ip, row.anomaly_reason)
      load()
    } catch (err) {
      setError(extractErrorMessage(err, 'Could not un-acknowledge this'))
    } finally {
      setBusyRow(null)
    }
  }

  function handleExport(format: 'csv' | 'xml') {
    setExporting(true)
    anomalySummaryApi
      .export(view, format)
      .catch(() => setError('Could not export the report'))
      .finally(() => setExporting(false))
  }

  return (
    <div>
      <h2>Anomaly summary</h2>
      <p className="page-hint">
        Every anomaly type each device (or vendor) has ever produced, counted from the very start of your data — not
        a rolling window like Log Search. Acknowledging a row marks it as reviewed/handled; it stays acknowledged
        until someone explicitly un-acknowledges it, even if the same type of anomaly happens again later.
      </p>

      <div className="form-actions" style={{ alignItems: 'center' }}>
        <label style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
          View
          <select value={view} onChange={(e) => setView(e.target.value as View)}>
            <option value="device">By device</option>
            <option value="vendor">By vendor (rollup)</option>
          </select>
        </label>
        <button type="button" disabled={exporting} onClick={() => handleExport('csv')}>
          {exporting ? 'Exporting…' : 'Export CSV'}
        </button>
        <button type="button" disabled={exporting} onClick={() => handleExport('xml')}>
          {exporting ? 'Exporting…' : 'Export XML'}
        </button>
      </div>

      {error && <p className="form-error">{error}</p>}
      {loading && <p className="page-hint">Loading…</p>}

      {view === 'device' && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Source IP</th>
              <th>Vendor</th>
              <th>Anomaly type</th>
              <th>Count</th>
              <th>First seen</th>
              <th>Last seen</th>
              <th>Status</th>
              {canManage && <th></th>}
            </tr>
          </thead>
          <tbody>
            {deviceRows?.map((r) => {
              const key = rowKey(r.source_ip, r.anomaly_reason)
              return (
                <tr key={key}>
                  <td>{r.hostname}</td>
                  <td className="mono">{r.source_ip}</td>
                  <td>{r.vendor}</td>
                  <td>{r.anomaly_reason}</td>
                  <td>{r.event_count.toLocaleString()}</td>
                  <td>{formatBeirutDateTime(r.first_seen)}</td>
                  <td>{formatBeirutDateTime(r.last_seen)}</td>
                  <td>
                    {r.acknowledged ? (
                      <span className="badge badge-scope-device">
                        Acknowledged{r.acknowledged_by && ` by ${r.acknowledged_by}`}
                        {r.note && <span title={r.note}> 📝</span>}
                      </span>
                    ) : (
                      <span className="badge badge-unresolved">Unhandled</span>
                    )}
                  </td>
                  {canManage && (
                    <td className="row-actions">
                      {r.acknowledged ? (
                        <button type="button" disabled={busyRow === key} onClick={() => handleUnacknowledge(r)}>
                          Un-acknowledge
                        </button>
                      ) : (
                        <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                          <input
                            type="text"
                            placeholder="note (optional)"
                            value={noteDrafts[key] ?? ''}
                            onChange={(e) => setNoteDrafts((prev) => ({ ...prev, [key]: e.target.value }))}
                            style={{ width: 140 }}
                          />
                          <button type="button" disabled={busyRow === key} onClick={() => handleAcknowledge(r)}>
                            Acknowledge
                          </button>
                        </div>
                      )}
                    </td>
                  )}
                </tr>
              )
            })}
            {deviceRows?.length === 0 && !loading && (
              <tr>
                <td colSpan={canManage ? 9 : 8}>No anomalies recorded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {view === 'vendor' && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Vendor</th>
              <th>Anomaly type</th>
              <th>Devices affected</th>
              <th>Total events</th>
              <th>First seen</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {vendorRows?.map((r) => (
              <tr key={`${r.vendor}::${r.anomaly_reason}`}>
                <td>{r.vendor}</td>
                <td>{r.anomaly_reason}</td>
                <td>{r.device_count.toLocaleString()}</td>
                <td>{r.event_count.toLocaleString()}</td>
                <td>{formatBeirutDateTime(r.first_seen)}</td>
                <td>{formatBeirutDateTime(r.last_seen)}</td>
              </tr>
            ))}
            {vendorRows?.length === 0 && !loading && (
              <tr>
                <td colSpan={6}>No anomalies recorded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  )
}
