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
  auto_discovered: boolean
  v3_user: string | null
  v3_level: string | null
  created_at: string
  updated_at: string
  has_community: boolean
  has_v3_auth: boolean
  has_v3_priv: boolean
}

export interface CredentialPoolImportInput {
  ip_or_cidr: string
  version: 'v1' | 'v2c'
  communities: string[]
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

export interface RelaySourceIp {
  id: string
  ip: string
  note: string | null
  created_at: string
}

export interface RelaySourceIpInput {
  ip: string
  note?: string
}

export type ResolutionMethod = 'snmp' | 'syslog_reported' | 'unresolved'
export type VendorSource = 'snmp' | 'passive' | 'unknown'

export interface Device {
  ip: string
  hostname: string
  vendor: string
  vendor_source: VendorSource
  model: string
  resolution_method: ResolutionMethod
  first_seen_in_window: string
  last_seen: string
  event_count: number
}

export interface DeviceListResponse {
  items: Device[]
  limit: number
  offset: number
  has_more: boolean
}

export interface DeviceSearchFilters {
  hostname?: string
  ip?: string
  vendor?: string
  start?: string
  end?: string
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
  anomaly_reasons: string[]
  resolution_method: ResolutionMethod
}

export interface LogSearchFilters {
  start?: string
  end?: string
  hostname?: string
  source_ip?: string
  vendor?: string
  program?: string
  severity?: string
  predicted_category?: string
  anomaly_reason?: string
  q?: string
  only_anomalies?: boolean
  limit?: number
  offset?: number
}

export interface LogSearchResponse {
  items: LogEntry[]
  limit: number
  offset: number
  has_more: boolean
}

export interface LogFilterOptions {
  vendors: string[]
  programs: string[]
}

export interface AlertRuleInput {
  name: string
  enabled: boolean
  window_minutes: number
  threshold: number
  cooldown_minutes: number
  hostname?: string
  source_ip?: string
  program?: string
  severity?: string
  predicted_category?: string
  only_anomalies: boolean
  webhook_url?: string
}

export interface AlertRule extends AlertRuleInput {
  id: string
  last_triggered_at: string | null
  created_at: string
  updated_at: string
}

export type ModelScope = 'device' | 'vendor'

export interface AnomalyWindow {
  window_start: string
  source_ip: string
  hostname: string
  vendor: string
  model_scope: ModelScope
  anomaly_score: number
  is_anomaly: boolean
  event_count: number
}

export interface AnomalyWindowFilters {
  start?: string
  end?: string
  source_ip?: string
  vendor?: string
  only_anomalies?: boolean
}

export interface AnomalyWindowListResponse {
  items: AnomalyWindow[]
  limit: number
  offset: number
  has_more: boolean
}

export interface QueryResult {
  columns: string[]
  rows: unknown[][]
  row_count: number
  truncated: boolean
  is_command: boolean
  message: string | null
}

export interface AlertEvent {
  id: string
  rule_id: string
  triggered_at: string
  window_start: string
  window_end: string
  matched_count: number
  sample_message: string
  notified: boolean
  notify_error: string | null
}

export interface DeviceAnomalySummaryRow {
  source_ip: string
  hostname: string
  vendor: string
  anomaly_reason: string
  event_count: number
  first_seen: string
  last_seen: string
  acknowledged: boolean
  acknowledged_by: string | null
  acknowledged_at: string | null
  note: string | null
}

export interface VendorAnomalySummaryRow {
  vendor: string
  anomaly_reason: string
  device_count: number
  event_count: number
  first_seen: string
  last_seen: string
}

export interface DeviceCategorySummaryRow {
  source_ip: string
  hostname: string
  vendor: string
  predicted_category: string
  event_count: number
  first_seen: string
  last_seen: string
}

export interface VendorCategorySummaryRow {
  vendor: string
  predicted_category: string
  device_count: number
  event_count: number
  first_seen: string
  last_seen: string
}
