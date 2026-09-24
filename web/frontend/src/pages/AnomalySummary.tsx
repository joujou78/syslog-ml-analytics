import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { anomalySummaryApi } from '../api/anomalySummary'
import { useAuth } from '../auth/AuthContext'
import type {
  DeviceAnomalySummaryRow, DeviceCategorySummaryRow, VendorAnomalySummaryRow, VendorCategorySummaryRow,
} from '../types'
import { extractErrorMessage } from '../utils/errors'
import { formatBeirutDateTime } from '../utils/time'

type View = 'device' | 'vendor'
type Metric = 'anomaly' | 'category'

function logSearchLink(params: Record<string, string>) {
  return `/logs?${new URLSearchParams(params).toString()}`
}

function rowKey(sourceIp: string, type: string) {
  return `${sourceIp}::${type}`
}

export function AnomalySummary() {
  const { user } = useAuth()
  const canManage = user?.role === 'admin' || user?.role === 'analyst'

  const [view, setView] = useState<View>('device')
  const [metric, setMetric] = useState<Metric>('anomaly')

  const [anomalyDeviceRows, setAnomalyDeviceRows] = useState<DeviceAnomalySummaryRow[] | null>(null)
  const [anomalyVendorRows, setAnomalyVendorRows] = useState<VendorAnomalySummaryRow[] | null>(null)
  const [categoryDeviceRows, setCategoryDeviceRows] = useState<DeviceCategorySummaryRow[] | null>(null)
  const [categoryVendorRows, setCategoryVendorRows] = useState<VendorCategorySummaryRow[] | null>(null)

  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)
  const [exporting, setExporting] = useState(false)
  const [noteDrafts, setNoteDrafts] = useState<Record<string, string>>({})
  const [busyRow, setBusyRow] = useState<string | null>(null)

  const load = () => {
    setLoading(true)
    setError(null)
    let request: Promise<unknown>
    if (metric === 'anomaly') {
      request = view === 'device' ? anomalySummaryApi.devices().then(setAnomalyDeviceRows) : anomalySummaryApi.vendors().then(setAnomalyVendorRows)
    } else {
      request = view === 'device' ? anomalySummaryApi.devicesByCategory().then(setCategoryDeviceRows) : anomalySummaryApi.vendorsByCategory().then(setCategoryVendorRows)
    }
    request
      .catch(() => setError('Could not load the summary — is ClickHouse reachable from the API?'))
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    load()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, metric])

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
      .export(view, metric, format)
      .catch(() => setError('Could not export the report'))
      .finally(() => setExporting(false))
  }

  const typeColumnLabel = metric === 'anomaly' ? 'Anomaly type' : 'Category'

  return (
    <div>
      <h2>{metric === 'anomaly' ? 'Anomaly summary' : 'Category summary'}</h2>
      <p className="page-hint">
        {metric === 'anomaly' ? (
          <>
            Every anomaly type each device (or vendor) has ever produced, counted from the very start of your data —
            not a rolling window like Log Search. Acknowledging a row marks it as reviewed/handled; it stays
            acknowledged until someone explicitly un-acknowledges it, even if the same type of anomaly happens again
            later.
          </>
        ) : (
          <>
            Every message category (AUTH, SECURITY, HARDWARE, NETWORK, ...) each device (or vendor) has ever
            produced, counted from the very start of your data — covers all messages, not just anomalies, so there's
            nothing to acknowledge here.
          </>
        )}
      </p>

      <div className="form-actions" style={{ alignItems: 'center' }}>
        <label style={{ flexDirection: 'row', alignItems: 'center', gap: 8 }}>
          Metric
          <select value={metric} onChange={(e) => setMetric(e.target.value as Metric)}>
            <option value="anomaly">Anomaly type</option>
            <option value="category">Category</option>
          </select>
        </label>
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

      {view === 'device' && metric === 'anomaly' && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Source IP</th>
              <th>Vendor</th>
              <th>{typeColumnLabel}</th>
              <th>Count</th>
              <th>First seen</th>
              <th>Last seen</th>
              <th>Status</th>
              {canManage && <th></th>}
            </tr>
          </thead>
          <tbody>
            {anomalyDeviceRows?.map((r) => {
              const key = rowKey(r.source_ip, r.anomaly_reason)
              return (
                <tr key={key}>
                  <td>{r.hostname}</td>
                  <td className="mono">{r.source_ip}</td>
                  <td>{r.vendor}</td>
                  <td>{r.anomaly_reason}</td>
                  <td>
                    <Link to={logSearchLink({ source_ip: r.source_ip, anomaly_reason: r.anomaly_reason })}>
                      {r.event_count.toLocaleString()}
                    </Link>
                  </td>
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
            {anomalyDeviceRows?.length === 0 && !loading && (
              <tr>
                <td colSpan={canManage ? 9 : 8}>No anomalies recorded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {view === 'vendor' && metric === 'anomaly' && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Vendor</th>
              <th>{typeColumnLabel}</th>
              <th>Devices affected</th>
              <th>Total events</th>
              <th>First seen</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {anomalyVendorRows?.map((r) => (
              <tr key={`${r.vendor}::${r.anomaly_reason}`}>
                <td>{r.vendor}</td>
                <td>{r.anomaly_reason}</td>
                <td>{r.device_count.toLocaleString()}</td>
                <td>
                  <Link to={logSearchLink({ vendor: r.vendor, anomaly_reason: r.anomaly_reason })}>
                    {r.event_count.toLocaleString()}
                  </Link>
                </td>
                <td>{formatBeirutDateTime(r.first_seen)}</td>
                <td>{formatBeirutDateTime(r.last_seen)}</td>
              </tr>
            ))}
            {anomalyVendorRows?.length === 0 && !loading && (
              <tr>
                <td colSpan={6}>No anomalies recorded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {view === 'device' && metric === 'category' && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Hostname</th>
              <th>Source IP</th>
              <th>Vendor</th>
              <th>{typeColumnLabel}</th>
              <th>Count</th>
              <th>First seen</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {categoryDeviceRows?.map((r) => (
              <tr key={rowKey(r.source_ip, r.predicted_category)}>
                <td>{r.hostname}</td>
                <td className="mono">{r.source_ip}</td>
                <td>{r.vendor}</td>
                <td>{r.predicted_category}</td>
                <td>
                  <Link to={logSearchLink({ source_ip: r.source_ip, predicted_category: r.predicted_category })}>
                    {r.event_count.toLocaleString()}
                  </Link>
                </td>
                <td>{formatBeirutDateTime(r.first_seen)}</td>
                <td>{formatBeirutDateTime(r.last_seen)}</td>
              </tr>
            ))}
            {categoryDeviceRows?.length === 0 && !loading && (
              <tr>
                <td colSpan={7}>No events recorded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      )}

      {view === 'vendor' && metric === 'category' && (
        <table className="data-table">
          <thead>
            <tr>
              <th>Vendor</th>
              <th>{typeColumnLabel}</th>
              <th>Devices affected</th>
              <th>Total events</th>
              <th>First seen</th>
              <th>Last seen</th>
            </tr>
          </thead>
          <tbody>
            {categoryVendorRows?.map((r) => (
              <tr key={`${r.vendor}::${r.predicted_category}`}>
                <td>{r.vendor}</td>
                <td>{r.predicted_category}</td>
                <td>{r.device_count.toLocaleString()}</td>
                <td>
                  <Link to={logSearchLink({ vendor: r.vendor, predicted_category: r.predicted_category })}>
                    {r.event_count.toLocaleString()}
                  </Link>
                </td>
                <td>{formatBeirutDateTime(r.first_seen)}</td>
                <td>{formatBeirutDateTime(r.last_seen)}</td>
              </tr>
            ))}
            {categoryVendorRows?.length === 0 && !loading && (
              <tr>
                <td colSpan={6}>No events recorded yet.</td>
              </tr>
            )}
          </tbody>
        </table>
      )}
    </div>
  )
}
