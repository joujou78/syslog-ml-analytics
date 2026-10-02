// Every timestamp in the API is stored and transmitted as UTC (see
// clickhouse/init.sql's event_time/received_at columns and consumer.py) --
// deliberately kept that way rather than storing local time, since UTC is
// what every window/TTL/comparison query in this codebase assumes. This is
// purely a display-time conversion to Beirut local time (the operators'
// own timezone), done with a real IANA zone (not a fixed offset) so it
// stays correct across DST if Lebanon observes it, unlike the backend's
// flat-offset relay timestamp correction (see README's
// RELAY_TIMEZONE_OFFSET_HOURS section) which exists to fix bad *data*,
// not to convert good data for display.
const BEIRUT_TZ = 'Asia/Beirut'

// The API's datetime fields round-trip clickhouse-connect's own naive UTC
// values (see driver/dataconv.py's `datetime.utcfromtimestamp` -- no
// tzinfo attached) through Pydantic, which serializes a naive datetime
// with no 'Z'/offset suffix at all, e.g. "2026-09-24T10:00:00". JS's Date
// constructor treats a date-time string with no timezone designator as
// LOCAL time, not UTC -- silently wrong on any viewer whose OS/browser
// timezone isn't UTC, which for this app's own Beirut-based viewers it
// isn't. Confirmed: `new Date("2026-09-24T10:00:00")` under TZ=Asia/Beirut
// resolves to 07:00 UTC, three hours off the intended 10:00 UTC. Since
// every timestamp from this API really is UTC (see the comment above),
// this appends 'Z' before parsing whenever the string doesn't already
// carry an explicit offset, rather than trusting Date's ambiguous default.
function toUtcDate(iso: string): Date {
  return new Date(/[Zz]|[+-]\d{2}:\d{2}$/.test(iso) ? iso : `${iso}Z`)
}

export function formatBeirutDateTime(iso: string): string {
  return toUtcDate(iso).toLocaleString(undefined, { timeZone: BEIRUT_TZ })
}

export function formatBeirutTime(date: Date): string {
  return date.toLocaleTimeString(undefined, { timeZone: BEIRUT_TZ })
}

// datetime-local inputs (and the Log Assistant/Log Search filters that
// read from them) expect "YYYY-MM-DDTHH:MM" in UTC, not a display string --
// this stays in UTC on purpose, unlike the Beirut-local formatters above.
function toDatetimeLocalUtc(date: Date): string {
  return date.toISOString().slice(0, 16)
}

// The Asia/Beirut UTC offset (in minutes, Beirut minus UTC) that applies
// at the given instant -- not a fixed constant, since Lebanon observes
// DST, so the offset shifts across the year.
function beirutOffsetMinutes(instant: Date): number {
  const dtf = new Intl.DateTimeFormat('en-US', {
    timeZone: BEIRUT_TZ, hour12: false,
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
  const parts: Record<string, string> = {}
  for (const part of dtf.formatToParts(instant)) parts[part.type] = part.value
  // Some runtimes render midnight as hour '24' under hour12: false --
  // normalize so Date.UTC doesn't silently roll into the next day.
  const hour = parts.hour === '24' ? '00' : parts.hour
  const asIfUtc = Date.UTC(+parts.year, +parts.month - 1, +parts.day, +hour, +parts.minute, +parts.second)
  return Math.round((asIfUtc - instant.getTime()) / 60_000)
}

// Converts a UTC instant (from the API/URL) into the "YYYY-MM-DDTHH:MM"
// string a <input type="datetime-local"> needs to display it as Beirut
// local time -- the filter-bar counterpart to formatBeirutDateTime's
// read-only display. Added after a real mix-up: Log Assistant's Start/End
// inputs showed raw UTC with no label while its own "Cited log lines"
// table showed Beirut local time, making a correct query look 3 hours
// off at a glance. Log Search, Devices, and Anomaly Windows' filter bars
// had the identical gap -- fixed the same way, not just on that one page.
export function toDatetimeLocalBeirut(iso: string): string {
  const instant = toUtcDate(iso)
  const shifted = new Date(instant.getTime() + beirutOffsetMinutes(instant) * 60_000)
  return shifted.toISOString().slice(0, 16)
}

// The inverse: a <input type="datetime-local">'s value (entered as Beirut
// local wall-clock time) back to the UTC "YYYY-MM-DDTHH:MM" string the
// API/URL actually expects. The offset is looked up using the typed value
// itself as the reference instant -- the only way this could be off is a
// value that falls exactly within a DST transition's lost/repeated hour,
// which this UI has no way to disambiguate either.
export function fromDatetimeLocalBeirut(value: string): string {
  const naive = new Date(`${value}:00Z`)
  const actual = new Date(naive.getTime() - beirutOffsetMinutes(naive) * 60_000)
  return actual.toISOString().slice(0, 16)
}

// Pads a single instant (e.g. an anomaly window's start, or a reason's
// last_seen) into a {start, end} range around it, for "Explain with AI"
// links that need more surrounding context than the flagged instant alone
// -- an LLM asked about one bare timestamp has nothing to reason over.
//
// `end` is clamped to now: for a still-recent/ongoing anomaly (last_seen or
// window_start within `afterMinutes` of the current time -- the exact case
// an analyst most wants "Explain" to work for), the un-clamped end would
// land in the future. Confirmed in practice: a device last seen logging an
// anomaly 5 minutes ago, padded +15 minutes, produced a query window ending
// 10 minutes from now -- guaranteed to find nothing (there's no data yet
// for a time that hasn't happened), independent of anything the indexer
// does or doesn't have caught up on.
export function padWindow(iso: string, beforeMinutes: number, afterMinutes: number): { start: string; end: string } {
  const center = toUtcDate(iso)
  const start = new Date(center.getTime() - beforeMinutes * 60_000)
  const end = new Date(Math.min(center.getTime() + afterMinutes * 60_000, Date.now()))
  return { start: toDatetimeLocalUtc(start), end: toDatetimeLocalUtc(end) }
}

// A device-silence duration in minutes (often hours+) reads better as
// "5h 12m" than a bare minute count -- this only goes up to hours since
// nothing in this codebase's silence detection expects multi-day gaps to
// be common enough to need a "d" unit too.
export function formatDurationMinutes(totalMinutes: number): string {
  const minutes = Math.round(totalMinutes)
  const hours = Math.floor(minutes / 60)
  const remainder = minutes % 60
  return hours > 0 ? `${hours}h ${remainder}m` : `${remainder}m`
}
