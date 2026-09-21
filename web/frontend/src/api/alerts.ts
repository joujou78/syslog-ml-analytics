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
}
