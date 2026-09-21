export type Role = 'admin' | 'analyst' | 'viewer'

export interface User {
  id: string
  username: string
  role: Role
  is_active: boolean
}

export type SnmpVersion = 'v1' | 'v2c' | 'v3'

export interface Credential {
  id: string
  ip_or_cidr: string
  version: SnmpVersion
  v3_user: string | null
  v3_level: string | null
  created_at: string
  updated_at: string
  has_community: boolean
  has_v3_auth: boolean
  has_v3_priv: boolean
}

export interface CredentialInput {
  ip_or_cidr: string
  version: SnmpVersion
  community?: string
  v3_user?: string
  v3_level?: 'noAuthNoPriv' | 'authNoPriv' | 'authPriv'
  v3_auth_proto?: 'MD5' | 'SHA'
  v3_auth_pass?: string
  v3_priv_proto?: 'DES' | 'AES'
  v3_priv_pass?: string
}

export type ResolutionMethod = 'snmp' | 'syslog_reported' | 'unresolved'

export interface Device {
  ip: string
  hostname: string
  vendor: string
  model: string
  resolution_method: ResolutionMethod
  first_seen_in_window: string
  last_seen: string
  event_count: number
}

export interface ResolutionSummary {
  resolution_method: ResolutionMethod
  device_count: number
}

export interface LogEntry {
  event_time: string
  source_ip: string
  hostname: string
  vendor: string
  severity: string
  program: string
  pid: number | null
  message: string
  predicted_category: string
  predicted_confidence: number
  is_anomaly: boolean
  resolution_method: ResolutionMethod
}

export interface LogSearchFilters {
  start?: string
  end?: string
  hostname?: string
  source_ip?: string
  program?: string
  severity?: string
  predicted_category?: string
  q?: string
  limit?: number
  offset?: number
}

export interface LogSearchResponse {
  items: LogEntry[]
  limit: number
  offset: number
  has_more: boolean
}
