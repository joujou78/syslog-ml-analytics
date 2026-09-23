import { useEffect, useRef, useState } from 'react'
import { credentialsApi } from '../api/credentials'
import type { Credential, CredentialInput, SnmpVersion } from '../types'
import { extractErrorMessage } from '../utils/errors'
import { formatBeirutDateTime } from '../utils/time'

const EMPTY_FORM: CredentialInput = {
  ip_or_cidr: '',
  version: 'v2c',
  community: '',
  v3_user: '',
  v3_level: 'authPriv',
  v3_auth_proto: 'SHA',
  v3_auth_pass: '',
  v3_priv_proto: 'AES',
  v3_priv_pass: '',
}

export function Credentials() {
  const [credentials, setCredentials] = useState<Credential[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [form, setForm] = useState<CredentialInput>(EMPTY_FORM)
  const [editingId, setEditingId] = useState<string | null>(null)
  const [submitting, setSubmitting] = useState(false)

  const [poolScope, setPoolScope] = useState('0.0.0.0/0')
  const [poolVersion, setPoolVersion] = useState<'v1' | 'v2c'>('v2c')
  const [poolCommunities, setPoolCommunities] = useState('')
  const [poolError, setPoolError] = useState<string | null>(null)
  const [poolResult, setPoolResult] = useState<string | null>(null)
  const [poolSubmitting, setPoolSubmitting] = useState(false)

  const editFormRef = useRef<HTMLFormElement>(null)

  const load = () => credentialsApi.list().then(setCredentials).catch(() => setError('Could not load credentials'))

  useEffect(() => {
    load()
  }, [])

  const startEdit = (cred: Credential) => {
    setEditingId(cred.id)
    setForm({
      ip_or_cidr: cred.ip_or_cidr,
      version: cred.version,
      community: '',
      v3_user: cred.v3_user ?? '',
      v3_level: (cred.v3_level as CredentialInput['v3_level']) ?? 'authPriv',
      v3_auth_proto: 'SHA',
      v3_auth_pass: '',
      v3_priv_proto: 'AES',
      v3_priv_pass: '',
    })
    // With a long credential list (e.g. after a bulk pool import), the edit
    // form at the top of the page is often off-screen from a row further
    // down -- without this, clicking Edit looks like it does nothing.
    editFormRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' })
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
      if (editingId) {
        await credentialsApi.update(editingId, form)
      } else {
        await credentialsApi.create(form)
      }
      cancelEdit()
      await load()
    } catch (err) {
      setError(extractErrorMessage(err, 'Could not save credential'))
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this credential? Devices matching it will stop resolving via SNMP.')) return
    await credentialsApi.remove(id)
    await load()
  }

  const handlePoolImport = async (e: React.FormEvent) => {
    e.preventDefault()
    setPoolError(null)
    setPoolResult(null)
    const communities = poolCommunities.split('\n').map((c) => c.trim()).filter(Boolean)
    if (communities.length === 0) {
      setPoolError('Paste at least one community string, one per line')
      return
    }
    setPoolSubmitting(true)
    try {
      const res = await credentialsApi.importPool({ ip_or_cidr: poolScope, version: poolVersion, communities })
      setPoolResult(`Imported ${res.imported} candidate credential(s) scoped to ${poolScope}.`)
      setPoolCommunities('')
      await load()
    } catch (err) {
      setPoolError(extractErrorMessage(err, 'Could not import the credential pool'))
    } finally {
      setPoolSubmitting(false)
    }
  }

  return (
    <div>
      <h2>SNMP Credentials</h2>
      <p className="page-hint">
        Only IPs/subnets listed here are ever queried via SNMP — nothing is guessed. Add an entry per device or
        per subnet that shares a community/user.
      </p>

      <form ref={editFormRef} className="credential-form" onSubmit={handleSubmit}>
        <h3>{editingId ? 'Edit credential' : 'Add credential'}</h3>
        <div className="form-grid">
          <label>
            IP or CIDR
            <input
              value={form.ip_or_cidr}
              onChange={(e) => setForm({ ...form, ip_or_cidr: e.target.value })}
              placeholder="10.10.1.5 or 10.10.2.0/24"
              required
            />
          </label>
          <label>
            SNMP version
            <select
              value={form.version}
              onChange={(e) => setForm({ ...form, version: e.target.value as SnmpVersion })}
            >
              <option value="v2c">v2c</option>
              <option value="v1">v1</option>
              <option value="v3">v3</option>
            </select>
          </label>

          {form.version !== 'v3' ? (
            <label>
              Community {editingId && '(leave blank to keep current)'}
              <input
                type="password"
                value={form.community}
                onChange={(e) => setForm({ ...form, community: e.target.value })}
                required={!editingId}
              />
            </label>
          ) : (
            <>
              <label>
                Username
                <input value={form.v3_user} onChange={(e) => setForm({ ...form, v3_user: e.target.value })} required />
              </label>
              <label>
                Security level
                <select
                  value={form.v3_level}
                  onChange={(e) => setForm({ ...form, v3_level: e.target.value as CredentialInput['v3_level'] })}
                >
                  <option value="authPriv">authPriv</option>
                  <option value="authNoPriv">authNoPriv</option>
                  <option value="noAuthNoPriv">noAuthNoPriv</option>
                </select>
              </label>
              <label>
                Auth protocol
                <select
                  value={form.v3_auth_proto}
                  onChange={(e) => setForm({ ...form, v3_auth_proto: e.target.value as CredentialInput['v3_auth_proto'] })}
                >
                  <option value="SHA">SHA</option>
                  <option value="MD5">MD5</option>
                </select>
              </label>
              <label>
                Auth passphrase {editingId && '(leave blank to keep current)'}
                <input
                  type="password"
                  value={form.v3_auth_pass}
                  onChange={(e) => setForm({ ...form, v3_auth_pass: e.target.value })}
                />
              </label>
              <label>
                Priv protocol
                <select
                  value={form.v3_priv_proto}
                  onChange={(e) => setForm({ ...form, v3_priv_proto: e.target.value as CredentialInput['v3_priv_proto'] })}
                >
                  <option value="AES">AES</option>
                  <option value="DES">DES</option>
                </select>
              </label>
              <label>
                Priv passphrase {editingId && '(leave blank to keep current)'}
                <input
                  type="password"
                  value={form.v3_priv_pass}
                  onChange={(e) => setForm({ ...form, v3_priv_pass: e.target.value })}
                />
              </label>
            </>
          )}
        </div>

        {error && <p className="form-error">{error}</p>}

        <div className="form-actions">
          <button type="submit" disabled={submitting}>
            {editingId ? 'Save changes' : 'Add credential'}
          </button>
          {editingId && (
            <button type="button" onClick={cancelEdit}>
              Cancel
            </button>
          )}
        </div>
      </form>

      <form className="credential-form" onSubmit={handlePoolImport}>
        <h3>Bulk import a community pool</h3>
        <p className="page-hint">
          Have a known set of community strings but no per-device mapping? Paste them here (one per line). The
          resolver tries each one against a device until it gets a real SNMP response, then saves the one that
          worked as that device's own credential (tagged "auto-discovered" below) so future checks query it
          directly instead of re-trying the whole pool.
        </p>
        <div className="form-grid">
          <label>
            Scope (IP or CIDR these communities apply to)
            <input value={poolScope} onChange={(e) => setPoolScope(e.target.value)} placeholder="0.0.0.0/0" required />
          </label>
          <label>
            SNMP version
            <select value={poolVersion} onChange={(e) => setPoolVersion(e.target.value as 'v1' | 'v2c')}>
              <option value="v2c">v2c</option>
              <option value="v1">v1</option>
            </select>
          </label>
        </div>
        <label>
          Community strings (one per line)
          <textarea
            value={poolCommunities}
            onChange={(e) => setPoolCommunities(e.target.value)}
            rows={8}
            placeholder={'community1\ncommunity2\ncommunity3'}
          />
        </label>
        {poolError && <p className="form-error">{poolError}</p>}
        {poolResult && <p className="page-hint">{poolResult}</p>}
        <div className="form-actions">
          <button type="submit" disabled={poolSubmitting}>
            Import pool
          </button>
        </div>
      </form>

      <table className="data-table">
        <thead>
          <tr>
            <th>IP / CIDR</th>
            <th>Version</th>
            <th>Details</th>
            <th>Updated</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          {credentials?.map((c) => (
            <tr key={c.id}>
              <td className="mono">
                {c.ip_or_cidr}
                {c.auto_discovered && (
                  <span className="vendor-hint" title="Automatically saved after a pool community matched this device via SNMP">
                    {' '}
                    (auto-discovered)
                  </span>
                )}
              </td>
              <td>{c.version}</td>
              <td>{c.version === 'v3' ? `user=${c.v3_user}, level=${c.v3_level}` : c.has_community ? 'community set' : 'no community set'}</td>
              <td>{formatBeirutDateTime(c.updated_at)}</td>
              <td className="row-actions">
                <button onClick={() => startEdit(c)}>Edit</button>
                <button onClick={() => handleDelete(c.id)}>Delete</button>
              </td>
            </tr>
          ))}
          {credentials?.length === 0 && (
            <tr>
              <td colSpan={5}>No credentials configured yet.</td>
            </tr>
          )}
        </tbody>
      </table>
    </div>
  )
}
