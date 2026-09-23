import { useEffect, useState } from 'react'
import { alertsApi } from '../api/alerts'
import { useAuth } from '../auth/AuthContext'
import type { AlertEvent, AlertRule, AlertRuleInput } from '../types'
import { extractErrorMessage } from '../utils/errors'
import { formatBeirutDateTime } from '../utils/time'

const SEVERITY_OPTIONS = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug']

const EMPTY_FORM: AlertRuleInput = {
  name: '',
  enabled: true,
  window_minutes: 5,
  threshold: 1,
  cooldown_minutes: 15,
  hostname: '',
  source_ip: '',
  program: '',
  severity: '',
  predicted_category: '',
  only_anomalies: false,
  webhook_url: '',
}

function toPayload(form: AlertRuleInput): AlertRuleInput {
  // Empty-string filters mean "no filter", not a literal empty match.
  return {
    ...form,
    hostname: form.hostname || undefined,
    source_ip: form.source_ip || undefined,
    program: form.program || undefined,
    severity: form.severity || undefined,
    predicted_category: form.predicted_category || undefined,
    webhook_url: form.webhook_url || undefined,
  }
}

export function Alerts() {
  const { user } = useAuth()
  const canManage = user?.role === 'admin' || user?.role === 'analyst'

  const [rules, setRules] = useState<AlertRule[] | null>(null)
  const [history, setHistory] = useState<AlertEvent[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [form, setForm] = useState<AlertRuleInput>(EMPTY_FORM)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const load = () => {
    alertsApi.listRules().then(setRules).catch(() => setError('Could not load alert rules'))
    alertsApi.history().then(setHistory).catch(() => setError('Could not load alert history'))
  }

  useEffect(() => {
    load()
  }, [])

  const startEdit = (rule: AlertRule) => {
    setEditingId(rule.id)
    setForm({
      name: rule.name,
      enabled: rule.enabled,
      window_minutes: rule.window_minutes,
      threshold: rule.threshold,
      cooldown_minutes: rule.cooldown_minutes,
      hostname: rule.hostname ?? '',
      source_ip: rule.source_ip ?? '',
      program: rule.program ?? '',
      severity: rule.severity ?? '',
      predicted_category: rule.predicted_category ?? '',
      only_anomalies: rule.only_anomalies,
      webhook_url: rule.webhook_url ?? '',
    })
  }

  const cancelEdit = () => {
    setEditingId(null)
    setForm(EMPTY_FORM)
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setSubmitting(true)
    try {
      const payload = toPayload(form)
      if (editingId) {
        await alertsApi.updateRule(editingId, payload)
      } else {
        await alertsApi.createRule(payload)
      }
      cancelEdit()
      load()
    } catch (err) {
      setError(extractErrorMessage(err, 'Could not save alert rule'))
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this alert rule? Its history will remain, but it will stop evaluating.')) return
    await alertsApi.deleteRule(id)
    load()
  }

  const ruleName = (ruleId: string) => rules?.find((r) => r.id === ruleId)?.name ?? ruleId

  return (
    <div>
      <h2>Alerts</h2>
      <p className="page-hint">
        A rule fires when at least <em>threshold</em> matching events occur within the trailing <em>window</em>,
        and won't fire again until <em>cooldown</em> has passed since its last trigger. Leave a filter blank to
        match any value for that field.
      </p>

      {canManage && (
        <form className="credential-form" onSubmit={handleSubmit}>
          <h3>{editingId ? 'Edit rule' : 'Add rule'}</h3>
          <div className="form-grid">
            <label>
              Name
              <input value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
            </label>
            <label>
              Enabled
              <select
                value={form.enabled ? 'true' : 'false'}
                onChange={(e) => setForm({ ...form, enabled: e.target.value === 'true' })}
              >
                <option value="true">Yes</option>
                <option value="false">No</option>
              </select>
            </label>
            <label>
              Window (minutes)
              <input
                type="number"
                min={1}
                max={1440}
                value={form.window_minutes}
                onChange={(e) => setForm({ ...form, window_minutes: Number(e.target.value) })}
                required
              />
            </label>
            <label>
              Threshold (event count)
              <input
                type="number"
                min={1}
                value={form.threshold}
                onChange={(e) => setForm({ ...form, threshold: Number(e.target.value) })}
                required
              />
            </label>
            <label>
              Cooldown (minutes)
              <input
                type="number"
                min={1}
                max={10080}
                value={form.cooldown_minutes}
                onChange={(e) => setForm({ ...form, cooldown_minutes: Number(e.target.value) })}
                required
              />
            </label>
            <label>
              Severity
              <select value={form.severity ?? ''} onChange={(e) => setForm({ ...form, severity: e.target.value })}>
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
                value={form.predicted_category ?? ''}
                onChange={(e) => setForm({ ...form, predicted_category: e.target.value })}
                placeholder="e.g. AUTH, SECURITY"
              />
            </label>
            <label>
              Hostname
              <input value={form.hostname ?? ''} onChange={(e) => setForm({ ...form, hostname: e.target.value })} />
            </label>
            <label>
              Source IP
              <input value={form.source_ip ?? ''} onChange={(e) => setForm({ ...form, source_ip: e.target.value })} />
            </label>
            <label>
              Program
              <input value={form.program ?? ''} onChange={(e) => setForm({ ...form, program: e.target.value })} />
            </label>
            <label>
              Anomalies only
              <select
                value={form.only_anomalies ? 'true' : 'false'}
                onChange={(e) => setForm({ ...form, only_anomalies: e.target.value === 'true' })}
              >
                <option value="false">No — count all matching events</option>
                <option value="true">Yes — only events flagged is_anomaly</option>
              </select>
            </label>
            <label>
              Webhook URL (optional)
              <input
                value={form.webhook_url ?? ''}
                onChange={(e) => setForm({ ...form, webhook_url: e.target.value })}
                placeholder="https://example.com/hook or a Slack incoming webhook"
              />
            </label>
          </div>

          {error && <p className="form-error">{error}</p>}

          <div className="form-actions">
            <button type="submit" disabled={submitting}>
              {editingId ? 'Save changes' : 'Add rule'}
            </button>
            {editingId && (
              <button type="button" onClick={cancelEdit}>
                Cancel
              </button>
            )}
          </div>
        </form>
      )}

      {!canManage && error && <p className="form-error">{error}</p>}

      <h3>Rules</h3>
      <table className="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Enabled</th>
            <th>Condition</th>
            <th>Last triggered</th>
            {canManage && <th></th>}
          </tr>
        </thead>
        <tbody>
          {rules?.map((r) => (
            <tr key={r.id}>
              <td>{r.name}</td>
              <td>{r.enabled ? 'Yes' : 'No'}</td>
              <td>
                &ge;{r.threshold} event(s) in {r.window_minutes}m
                {r.severity && `, severity=${r.severity}`}
                {r.predicted_category && `, category=${r.predicted_category}`}
                {r.hostname && `, hostname=${r.hostname}`}
                {r.source_ip && `, ip=${r.source_ip}`}
                {r.program && `, program=${r.program}`}
                {r.only_anomalies && ', anomalies only'}
              </td>
              <td>{r.last_triggered_at ? formatBeirutDateTime(r.last_triggered_at) : 'Never'}</td>
              {canManage && (
                <td className="row-actions">
                  <button onClick={() => startEdit(r)}>Edit</button>
                  <button onClick={() => handleDelete(r.id)}>Delete</button>
                </td>
              )}
            </tr>
          ))}
          {rules?.length === 0 && (
            <tr>
              <td colSpan={canManage ? 5 : 4}>No alert rules configured yet.</td>
            </tr>
          )}
        </tbody>
      </table>

      <h3>Recent triggers</h3>
      <table className="data-table">
        <thead>
          <tr>
            <th>Rule</th>
            <th>Triggered</th>
            <th>Matched</th>
            <th>Sample message</th>
            <th>Notified</th>
          </tr>
        </thead>
        <tbody>
          {history?.map((h) => (
            <tr key={h.id}>
              <td>{ruleName(h.rule_id)}</td>
              <td>{formatBeirutDateTime(h.triggered_at)}</td>
              <td>{h.matched_count}</td>
              <td className="mono log-message">{h.sample_message}</td>
              <td>{h.notified ? 'Yes' : `No${h.notify_error ? ` (${h.notify_error})` : ''}`}</td>
            </tr>
          ))}
          {history?.length === 0 && (
            <tr>
              <td colSpan={5}>No alerts have fired yet.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
