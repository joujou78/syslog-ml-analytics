import { useState } from 'react'
import { queryConsoleApi } from '../api/queryConsole'
import type { QueryResult } from '../types'
import { extractErrorMessage } from '../utils/errors'

const EXAMPLE_QUERY = 'SELECT event_time, source_ip, hostname, message\nFROM syslog_ml.events\nORDER BY event_time DESC\nLIMIT 50'

export function QueryConsole() {
  const [query, setQuery] = useState(EXAMPLE_QUERY)
  const [result, setResult] = useState<QueryResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [running, setRunning] = useState(false)

  function runQuery(e: React.FormEvent) {
    e.preventDefault()
    if (!query.trim()) return
    setRunning(true)
    setError(null)
    queryConsoleApi
      .execute(query)
      .then((res) => setResult(res))
      .catch((err) => {
        setResult(null)
        setError(extractErrorMessage(err, 'Query failed'))
      })
      .finally(() => setRunning(false))
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
      runQuery(e)
    }
  }

  function formatCell(value: unknown): string {
    if (value === null || value === undefined) return ''
    if (Array.isArray(value)) return `[${value.join(', ')}]`
    if (typeof value === 'object') return JSON.stringify(value)
    return String(value)
  }

  return (
    <div>
      <h2>Query console</h2>
      <p className="form-error" style={{ marginBottom: 16 }}>
        Full, unrestricted SQL access against ClickHouse — including <code>ALTER</code>, <code>DELETE</code>,{' '}
        <code>DROP</code>, and <code>TRUNCATE</code>. There is no undo. Every query run here is permanently logged
        (with the full query text) to the audit log before it executes, whether or not it succeeds. Only use this if
        you understand what the query does.
      </p>

      <form onSubmit={runQuery}>
        <label>
          SQL query
          <textarea
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            rows={10}
            className="mono"
            spellCheck={false}
            style={{ width: '100%', fontSize: 13 }}
          />
        </label>
        <div className="form-actions">
          <button type="submit" disabled={running}>
            {running ? 'Running…' : 'Run (Ctrl+Enter)'}
          </button>
        </div>
      </form>

      {error && <p className="form-error">{error}</p>}

      {result?.is_command && <p className="page-hint">{result.message}</p>}

      {result && !result.is_command && (
        <>
          <p className="page-hint">
            {result.row_count} row(s) returned{result.truncated && ' — truncated at 1,000 rows'}
          </p>
          <div style={{ overflowX: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  {result.columns.map((col) => (
                    <th key={col}>{col}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {result.rows.map((row, i) => (
                  <tr key={i}>
                    {row.map((cell, j) => (
                      <td key={j} className="mono">
                        {formatCell(cell)}
                      </td>
                    ))}
                  </tr>
                ))}
                {result.rows.length === 0 && (
                  <tr>
                    <td colSpan={result.columns.length || 1}>No rows returned.</td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  )
}
