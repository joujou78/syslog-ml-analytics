import { apiClient } from './client'
import type { AuditLogEntry } from '../types'

export const auditApi = {
  list: (params: { action?: string; since?: string } = {}) =>
    apiClient.get<AuditLogEntry[]>('/audit', { params }).then((r) => r.data),
  actions: () => apiClient.get<string[]>('/audit/actions').then((r) => r.data),
}
