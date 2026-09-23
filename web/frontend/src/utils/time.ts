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

export function formatBeirutDateTime(iso: string): string {
  return new Date(iso).toLocaleString(undefined, { timeZone: BEIRUT_TZ })
}

export function formatBeirutTime(date: Date): string {
  return date.toLocaleTimeString(undefined, { timeZone: BEIRUT_TZ })
}
