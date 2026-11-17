import { apiClient } from './client'
import type { AlertEvent, AlertRule, AlertRuleInput } from '../types'

export const alertsApi = {
  listRules: () => apiClient.get<AlertRule[]>('/alerts/rules').then((r) => r.data),
  createRule: (payload: AlertRuleInput) => apiClient.post<AlertRule>('/alerts/rules', payload).then((r) => r.data),
  updateRule: (id: string, payload: AlertRuleInput) =>
    apiClient.put<AlertRule>(`/alerts/rules/${id}`, payload).then((r) => r.data),
  deleteRule: (id: string) => apiClient.delete(`/alerts/rules/${id}`),
  history: (ruleId?: string) =>
    apiClient.get<AlertEvent[]>('/alerts/history', { params: ruleId ? { rule_id: ruleId } : {} }).then((r) => r.data),

  export: async (format: 'csv' | 'xml', ruleId?: string) => {
    const response = await apiClient.get('/alerts/export', {
      params: { format, ...(ruleId ? { rule_id: ruleId } : {}) },
      responseType: 'blob',
    })
    const disposition = response.headers['content-disposition'] as string | undefined
    const filename = disposition?.match(/filename="?([^"]+)"?/)?.[1] ?? `alert_events.${format}`
    const url = URL.createObjectURL(response.data as Blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  },
}
