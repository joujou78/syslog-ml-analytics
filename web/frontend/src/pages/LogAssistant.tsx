import { useEffect, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { logAssistantApi } from '../api/logAssistant'
import type { LogAssistantQuery, LogHit } from '../types'
import { extractErrorMessage } from '../utils/errors'
import { formatBeirutDateTime } from '../utils/time'

// Same idea as Logs.tsx's filtersFromSearchParams -- lets Anomaly Windows/
// Anomaly Summary's "Explain with AI" links land on a pre-filled question
// instead of an empty box. Read once on mount, not kept in sync afterward.
function queryFromSearchParams(params: URLSearchParams): LogAssistantQuery | null {
  const question = params.get('question')
  if (!question) return null
  const query: LogAssistantQuery = { question }
  const sourceIp = params.get('source_ip')
  const vendor = params.get('vendor')
  const start = params.get('start')
  const end = params.get('end')
  if (sourceIp) query.source_ip = sourceIp
  if (vendor) query.vendor = vendor
  if (start) query.start = start
  if (end) query.end = end
  return query
}

function logSearchLink(hit: LogHit) {
  const params = new URLSearchParams({
    source_ip: hit.source_ip,
    start: hit.event_time.slice(0, 16),
  })
  return `/logs?${params.toString()}`
}

function SourcesTable({ sources }: { sources: LogHit[] }) {
  if (sources.length === 0) {
    return <p className="page-hint">No related log lines were found.</p>
  }
  return (
    <table className="data-table">
      <thead>
        <tr>
          <th>Time</th>
          <th>Hostname</th>
          <th>Vendor</th>
          <th>Severity</th>
          <th>Program</th>
          <th>Message</th>
          <th>Relevance</th>
          <th></th>
        </tr>
      </thead>
      <tbody>
        {sources.map((hit, i) => (
          <tr key={`${hit.source_ip}-${hit.event_time}-${i}`}>
            <td className="mono">{formatBeirutDateTime(hit.event_time)}</td>
            <td>{hit.hostname}</td>
            <td>{hit.vendor}</td>
            <td>
              <span className={`badge badge-severity-${hit.severity}`}>{hit.severity}</span>
            </td>
            <td>{hit.program}</td>
            <td>{hit.message}</td>
            <td className="mono">{hit.score.toFixed(3)}</td>
            <td>
              <Link to={logSearchLink(hit)}>View in Log Search</Link>
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  )
}

export function LogAssistant() {
  const [searchParams] = useSearchParams()
  const initialQuery = () => queryFromSearchParams(searchParams)

  const [question, setQuestion] = useState(() => initialQuery()?.question ?? '')
  const [sourceIp, setSourceIp] = useState(() => initialQuery()?.source_ip ?? '')
  const [vendor, setVendor] = useState(() => initialQuery()?.vendor ?? '')
  const [start, setStart] = useState(() => initialQuery()?.start ?? '')
  const [end, setEnd] = useState(() => initialQuery()?.end ?? '')

  const [answer, setAnswer] = useState<string | null>(null)
  const [model, setModel] = useState<string | null>(null)
  const [sources, setSources] = useState<LogHit[] | null>(null)
  const [loading, setLoading] = useState<'ask' | 'search' | null>(null)
  const [error, setError] = useState<string | null>(null)

  function currentQuery(): LogAssistantQuery {
    const query: LogAssistantQuery = { question }
    if (sourceIp) query.source_ip = sourceIp
    if (vendor) query.vendor = vendor
    if (start) query.start = start
    if (end) query.end = end
    return query
  }

  function runAsk(e?: React.FormEvent) {
    e?.preventDefault()
    if (!question.trim()) return
    setLoading('ask')
    setError(null)
    setAnswer(null)
    logAssistantApi
      .ask(currentQuery())
      .then((res) => {
        setAnswer(res.answer)
        setModel(res.model)
        setSources(res.sources)
      })
      .catch((err) =>
        setError(extractErrorMessage(err, 'Could not reach the Log Assistant — is OpenSearch/Ollama running?')),
      )
      .finally(() => setLoading(null))
  }

  function runSearchOnly() {
    if (!question.trim()) return
    setLoading('search')
    setError(null)
    setAnswer(null)
    logAssistantApi
      .search(currentQuery())
      .then((res) => setSources(res.items))
      .catch((err) =>
        setError(extractErrorMessage(err, 'Could not reach the Log Assistant — is OpenSearch/Ollama running?')),
      )
      .finally(() => setLoading(null))
  }

  useEffect(() => {
    // Auto-run only for a deep link that already carries a question (e.g.
    // an "Explain with AI" link from Anomaly Windows/Anomaly Summary) --
    // never on a bare page load, since the LLM call is slow and shouldn't
    // fire just from visiting the page.
    if (initialQuery()) runAsk()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  return (
    <div>
      <h2>Log Assistant</h2>
      <p className="page-hint">
        Ask a question in plain language and get an answer synthesized by a local LLM from the log lines it finds
        semantically related — separate from Log Search's exact-match filtering, this finds lines by <em>meaning</em>,
        even when they don't share the same words as your question. Runs entirely on-host (see README): nothing here
        is sent to an external service. The LLM call can take a while on CPU-only hardware — "Search only" skips it
        and just shows matching log lines directly.
      </p>

      <form className="credential-form" onSubmit={runAsk}>
        <label>
          Question
          <textarea
            rows={3}
            value={question}
            onChange={(e) => setQuestion(e.target.value)}
            placeholder="e.g. why has sw1 been logging interface errors this morning?"
          />
        </label>
        <div className="form-grid">
          <label>
            Source IP
            <input type="text" value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} />
          </label>
          <label>
            Vendor
            <input type="text" value={vendor} onChange={(e) => setVendor(e.target.value)} />
          </label>
          <label>
            Start
            <input type="datetime-local" value={start} onChange={(e) => setStart(e.target.value)} />
          </label>
          <label>
            End
            <input type="datetime-local" value={end} onChange={(e) => setEnd(e.target.value)} />
          </label>
        </div>
        <div className="form-actions">
          <button type="submit" disabled={loading !== null || !question.trim()}>
            {loading === 'ask' ? 'Asking…' : 'Ask'}
          </button>
          <button type="button" onClick={runSearchOnly} disabled={loading !== null || !question.trim()}>
            {loading === 'search' ? 'Searching…' : 'Search only'}
          </button>
        </div>
      </form>

      {error && <p className="form-error">{error}</p>}

      {answer && (
        <div className="assistant-answer">
          <strong>Answer{model ? ` (${model})` : ''}:</strong>
          <p>{answer}</p>
        </div>
      )}

      {sources && (
        <>
          <h3>{answer ? 'Cited log lines' : 'Matching log lines'}</h3>
          <SourcesTable sources={sources} />
        </>
      )}
    </div>
  )
}
