import { useEffect, useRef, useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { logAssistantApi } from '../api/logAssistant'
import type { LogAssistantQuery, LogHit } from '../types'
import { extractErrorMessage } from '../utils/errors'
import { formatBeirutDateTime, fromDatetimeLocalBeirut, toDatetimeLocalBeirut } from '../utils/time'

// extractErrorMessage's fallback only ever fires when the backend's own
// response has no JSON `detail` (see errors.ts) -- for OpenSearch/Ollama
// actually being unreachable, that's genuinely accurate, since
// log_assistant.py's routes DO attach a `detail` for that case (see
// _upstream_error, a 502). But a 504 comes from nginx itself, timing out
// before the backend ever responds -- nginx's own error page is plain
// HTML, not JSON, so it ALWAYS falls through to whatever generic fallback
// is passed in. Confirmed on net-flow: this generic wording repeatedly
// looked like "OpenSearch/Ollama isn't running" when the real cause was
// "the LLM is still generating and took longer than the timeout" --
// several rounds of debugging before landing on the actual fix
// (ollama_num_predict, see config.py) could have been shortened
// considerably by the error message itself saying so.
function logAssistantErrorFallback(err: unknown): string {
  const status = (err as { response?: { status?: number } })?.response?.status
  if (status === 504) {
    return 'The Log Assistant timed out before finishing — likely still processing under load (e.g. "Ask" generating a long answer), not OpenSearch/Ollama being down. Try a shorter/simpler question, or wait and retry.'
  }
  return 'Could not reach the Log Assistant — is OpenSearch/Ollama running?'
}

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

function SourcesTable({ sources, coverageNote }: { sources: LogHit[]; coverageNote: string | null }) {
  if (sources.length === 0) {
    // coverageNote (see log_assistant_service.py's build_coverage_note)
    // distinguishes "genuinely nothing happened" from "it happened but
    // the indexer hasn't embedded it yet" -- both looked identical as a
    // bare "No related log lines were found" before this existed,
    // confirmed as a recurring point of confusion in real use.
    return <p className="page-hint">{coverageNote ?? 'No related log lines were found.'}</p>
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

// Reveals `text` progressively, like a live chat reply being typed, instead
// of the full answer appearing all at once. Purely a client-side display
// effect -- the backend already returned the complete, final answer text in
// one response by the time this renders (see this project's own
// _post_chat_sync comment: real token-by-token streaming from Ollama over
// an async transport is confirmed to hang on this exact model/host, so
// that's deliberately not touched here). Keyed by the caller on turn.id, so
// a parent re-render (e.g. a later turn being added) doesn't restart an
// already-finished or in-progress animation.
function TypedText({ text }: { text: string }) {
  const [shown, setShown] = useState('')
  useEffect(() => {
    setShown('')
    if (!text) return
    let i = 0
    // A handful of characters per tick, not one -- the wait for the answer
    // itself is already long on CPU-only hardware; a literal one-char reveal
    // of a multi-hundred-character answer would tack on several more
    // seconds of pure animation on top of that.
    const charsPerTick = Math.max(1, Math.ceil(text.length / 120))
    const id = setInterval(() => {
      i += charsPerTick
      setShown(text.slice(0, i))
      if (i >= text.length) clearInterval(id)
    }, 12)
    return () => clearInterval(id)
  }, [text])
  const done = shown.length >= text.length
  return (
    <>
      {shown}
      {!done && <span className="chat-typing-cursor" aria-hidden="true" />}
    </>
  )
}

// One exchange in the thread: a question the user sent (with whatever
// filters were active at the time -- kept per-turn, not just globally,
// since filters can change between messages and a past turn should still
// show what it was actually answered against) plus however far its
// response has gotten. Each turn is answered independently by the backend
// -- no conversation memory -- so a later turn can't reference an earlier
// one; this is purely a display thread, not a stateful conversation. See
// the "best possible" discussion in this project's history for why: this
// model already needed several rounds of fixes for reliable single-turn
// reasoning, and layering real multi-turn memory on top would multiply
// that surface area rather than improve the experience.
interface ChatTurn {
  id: string
  kind: 'ask' | 'search'
  question: string
  filters: { sourceIp?: string; vendor?: string; start?: string; end?: string }
  status: 'pending' | 'done' | 'error'
  answer?: string
  model?: string
  sources?: LogHit[]
  coverageNote?: string | null
  error?: string
}

function filtersSummary(filters: ChatTurn['filters']): string | null {
  const parts: string[] = []
  if (filters.sourceIp) parts.push(`IP ${filters.sourceIp}`)
  if (filters.vendor) parts.push(`vendor ${filters.vendor}`)
  if (filters.start) parts.push(`from ${formatBeirutDateTime(filters.start)}`)
  if (filters.end) parts.push(`to ${formatBeirutDateTime(filters.end)}`)
  return parts.length ? parts.join(' · ') : null
}

export function LogAssistant() {
  const [searchParams] = useSearchParams()
  const initialQuery = () => queryFromSearchParams(searchParams)

  const [question, setQuestion] = useState('')
  const [sourceIp, setSourceIp] = useState(() => initialQuery()?.source_ip ?? '')
  const [vendor, setVendor] = useState(() => initialQuery()?.vendor ?? '')
  const [start, setStart] = useState(() => initialQuery()?.start ?? '')
  const [end, setEnd] = useState(() => initialQuery()?.end ?? '')
  const [showFilters, setShowFilters] = useState(() => Boolean(sourceIp || vendor || start || end))

  const [turns, setTurns] = useState<ChatTurn[]>([])
  const [pending, setPending] = useState<'ask' | 'search' | null>(null)
  const threadEndRef = useRef<HTMLDivElement>(null)

  function currentFilters(): ChatTurn['filters'] {
    const filters: ChatTurn['filters'] = {}
    if (sourceIp) filters.sourceIp = sourceIp
    if (vendor) filters.vendor = vendor
    if (start) filters.start = start
    if (end) filters.end = end
    return filters
  }

  function queryFor(questionText: string, filters: ChatTurn['filters']): LogAssistantQuery {
    const query: LogAssistantQuery = { question: questionText }
    if (filters.sourceIp) query.source_ip = filters.sourceIp
    if (filters.vendor) query.vendor = filters.vendor
    if (filters.start) query.start = filters.start
    if (filters.end) query.end = filters.end
    return query
  }

  // Catches an inverted range (end before start) immediately, client-side,
  // rather than waiting on a round trip -- the backend also rejects this
  // (see LogAssistantQuery's _validate_time_range), since a client-only
  // check can't be trusted as the sole guard, but a round trip for
  // something this checkable is pure friction. Confirmed in real use: an
  // inverted range doesn't error the old way, it silently becomes a query
  // that can never match anything, indistinguishable from a genuinely
  // empty result.
  function invalidRange(): string | null {
    if (start && end && end < start) return 'End must not be before start.'
    return null
  }

  function updateTurn(id: string, patch: Partial<ChatTurn>) {
    setTurns((prev) => prev.map((t) => (t.id === id ? { ...t, ...patch } : t)))
  }

  function send(kind: 'ask' | 'search', questionText: string) {
    const trimmed = questionText.trim()
    if (!trimmed) return
    const rangeError = invalidRange()
    if (rangeError) {
      // Not worth a whole turn in the thread for a client-side validation
      // error that never reached the backend -- surfaced the same way the
      // old single-form version did.
      window.alert(rangeError)
      return
    }
    const filters = currentFilters()
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
    setTurns((prev) => [...prev, { id, kind, question: trimmed, filters, status: 'pending' }])
    setQuestion('')
    setPending(kind)

    const query = queryFor(trimmed, filters)
    const request = kind === 'ask' ? logAssistantApi.ask(query) : logAssistantApi.search(query)
    request
      .then((res) => {
        if (kind === 'ask' && 'answer' in res) {
          updateTurn(id, { status: 'done', answer: res.answer, model: res.model, sources: res.sources })
        } else if ('items' in res) {
          updateTurn(id, { status: 'done', sources: res.items, coverageNote: res.coverage_note })
        }
      })
      .catch((err) => updateTurn(id, { status: 'error', error: extractErrorMessage(err, logAssistantErrorFallback(err)) }))
      .finally(() => setPending(null))
  }

  useEffect(() => {
    threadEndRef.current?.scrollIntoView({ behavior: 'smooth', block: 'end' })
  }, [turns])

  useEffect(() => {
    // Auto-run only for a deep link that already carries a question (e.g.
    // an "Explain with AI" link from Anomaly Windows/Anomaly Summary) --
    // never on a bare page load, since the LLM call is slow and shouldn't
    // fire just from visiting the page.
    const initial = initialQuery()
    if (initial) send('ask', initial.question)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    send('ask', question)
  }

  return (
    <div className="chat-page">
      <h2>Log Assistant</h2>
      <p className="page-hint">
        Ask a question in plain language and get an answer synthesized by a local LLM, backed by real queries against
        your log data — not just a guess from matching log lines. Runs entirely on-host (see README): nothing here is
        sent to an external service. Each question is answered independently (no memory of earlier questions in this
        thread). The LLM call can take a while on CPU-only hardware — "Search only" skips it and just shows matching
        log lines directly.
      </p>

      <div className="chat-thread">
        {turns.length === 0 && <p className="page-hint chat-empty">Ask something to get started.</p>}
        {turns.map((turn) => (
          <div key={turn.id} className="chat-turn">
            <div className="chat-bubble chat-bubble-user">
              <div className="chat-bubble-label">You{turn.kind === 'search' ? ' (search only)' : ''}</div>
              <div className="chat-bubble-text">{turn.question}</div>
              {filtersSummary(turn.filters) && <div className="chat-filters-hint">{filtersSummary(turn.filters)}</div>}
            </div>

            <div className="chat-bubble chat-bubble-assistant">
              {turn.status === 'pending' && (
                <div className="chat-bubble-label">
                  {turn.kind === 'ask' ? 'Asking' : 'Searching'}
                  <span className="chat-typing-dots">
                    <span /><span /><span />
                  </span>
                </div>
              )}
              {turn.status === 'error' && <p className="form-error">{turn.error}</p>}
              {turn.status === 'done' && (
                <>
                  {turn.kind === 'ask' && (
                    <>
                      <div className="chat-bubble-label">Answer{turn.model ? ` (${turn.model})` : ''}</div>
                      <p className="chat-bubble-text">
                        <TypedText key={turn.id} text={turn.answer ?? ''} />
                      </p>
                    </>
                  )}
                  {turn.sources && (
                    <>
                      <h3>{turn.kind === 'ask' ? 'Cited log lines' : 'Matching log lines'}</h3>
                      <SourcesTable sources={turn.sources} coverageNote={turn.coverageNote ?? null} />
                    </>
                  )}
                </>
              )}
            </div>
          </div>
        ))}
        <div ref={threadEndRef} />
      </div>

      <form className="chat-compose" onSubmit={handleSubmit}>
        <textarea
          rows={2}
          value={question}
          onChange={(e) => setQuestion(e.target.value)}
          onKeyDown={(e) => {
            // Enter sends, Shift+Enter inserts a newline -- the usual chat-box
            // convention, so the textarea doesn't need a separate send button
            // to feel natural, though the button is still there for mouse use.
            if (e.key === 'Enter' && !e.shiftKey) {
              e.preventDefault()
              send('ask', question)
            }
          }}
          placeholder="e.g. which device is noisiest today?"
        />
        <div className="chat-compose-actions">
          <button type="button" className="chat-filters-toggle" onClick={() => setShowFilters((v) => !v)}>
            {showFilters ? 'Hide filters' : 'Filters'}
            {!showFilters && filtersSummary(currentFilters()) ? ' •' : ''}
          </button>
          <div className="chat-compose-buttons">
            <button type="button" onClick={() => send('search', question)} disabled={pending !== null || !question.trim()}>
              {pending === 'search' ? 'Searching…' : 'Search only'}
            </button>
            <button type="submit" disabled={pending !== null || !question.trim()}>
              {pending === 'ask' ? 'Asking…' : 'Ask'}
            </button>
          </div>
        </div>

        {showFilters && (
          <div className="form-grid chat-filters-grid">
            <label>
              Source IP
              <input type="text" value={sourceIp} onChange={(e) => setSourceIp(e.target.value)} />
            </label>
            <label>
              Vendor
              <input type="text" value={vendor} onChange={(e) => setVendor(e.target.value)} />
            </label>
            <label>
              Start (Beirut time)
              <input
                type="datetime-local"
                value={start ? toDatetimeLocalBeirut(start) : ''}
                onChange={(e) => setStart(e.target.value ? fromDatetimeLocalBeirut(e.target.value) : '')}
              />
            </label>
            <label>
              End (Beirut time)
              <input
                type="datetime-local"
                value={end ? toDatetimeLocalBeirut(end) : ''}
                onChange={(e) => setEnd(e.target.value ? fromDatetimeLocalBeirut(e.target.value) : '')}
              />
            </label>
          </div>
        )}
      </form>
    </div>
  )
}
