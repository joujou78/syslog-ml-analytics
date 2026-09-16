import { useEffect, useState } from 'react'
import { credentialsApi } from '../api/credentials'
import type { Credential, CredentialInput, SnmpVersion } from '../types'

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
    } catch (err: any) {
      setError(err?.response?.data?.detail ?? 'Could not save credential')
    } finally {
      setSubmitting(false)
    }
  }

  const handleDelete = async (id: string) => {
    if (!confirm('Delete this credential? Devices matching it will stop resolving via SNMP.')) return
    await credentialsApi.remove(id)
    await load()
  }

  return (
    <div>
      <h2>SNMP Credentials</h2>
      <p className="page-hint">
        Only IPs/subnets listed here are ever queried via SNMP — nothing is guessed. Add an entry per device or
        per subnet that shares a community/user.
      </p>

      <form className="credential-form" onSubmit={handleSubmit}>
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
              <td className="mono">{c.ip_or_cidr}</td>
              <td>{c.version}</td>
              <td>{c.version === 'v3' ? `user=${c.v3_user}, level=${c.v3_level}` : c.has_community ? 'community set' : 'no community set'}</td>
              <td>{new Date(c.updated_at).toLocaleString()}</td>
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
