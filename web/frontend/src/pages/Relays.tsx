import { useEffect, useState } from 'react'
import { relaysApi } from '../api/relays'
import type { RelaySourceIp } from '../types'
import { extractErrorMessage } from '../utils/errors'
import { formatBeirutDateTime } from '../utils/time'

export function Relays() {
  const [relays, setRelays] = useState<RelaySourceIp[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [ip, setIp] = useState('')
  const [note, setNote] = useState('')
  const [submitting, setSubmitting] = useState(false)

  const load = () => relaysApi.list().then(setRelays).catch(() => setError('Could not load the relay list'))

  useEffect(() => {
    load()
  }, [])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      await relaysApi.create({ ip, note: note || undefined })
      setIp('')
      setNote('')
      await load()
    } catch (err) {
      setError(extractErrorMessage(err, 'Could not add this IP'))
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Remove this relay? Devices behind it will collapse back into one row under its own identity.')) return
    await relaysApi.remove(id)
    await load()
  }

  return (
    <div>
      <h2>Relay Source IPs</h2>
      <p className="page-hint">
        Network sources that forward other devices' syslog messages here (e.g. an existing collector) rather than
        sending their own logs directly. Listing a relay here lets the pipeline recover each real device's identity
        from the message body instead of collapsing every device behind it into one row, and corrects timestamps for
        relays that timestamp in local time instead of UTC. This is a deliberate, narrow allowlist, not something
        applied to all traffic — the in-message hostname is self-reported and could otherwise be spoofed by anything
        sending through that IP, so only list network sources you've confirmed are actual relays.
      </p>

      <form className="credential-form" onSubmit={handleSubmit}>
        <div className="form-grid">
          <label>
            IP address
            <input value={ip} onChange={(e) => setIp(e.target.value)} placeholder="192.168.247.33" required />
          </label>
          <label>
            Note (optional)
            <input value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. LogAnalyzer collector" />
          </label>
        </div>
        {error && <p className="form-error">{error}</p>}
        <div className="form-actions">
          <button type="submit" disabled={submitting}>
            Add relay
          </button>
        </div>
      </form>

      <table className="data-table">
        <thead>
          <tr>
            <th>IP</th>
            <th>Note</th>
            <th>Added</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {relays?.map((r) => (
            <tr key={r.id}>
              <td className="mono">{r.ip}</td>
              <td>{r.note ?? ''}</td>
              <td>{formatBeirutDateTime(r.created_at)}</td>
              <td className="row-actions">
                <button onClick={() => handleDelete(r.id)}>Delete</button>
              </td>
            </tr>
          ))}
          {relays?.length === 0 && (
            <tr>
              <td colSpan={4}>No relays configured — every source_ip is treated as a direct device.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
