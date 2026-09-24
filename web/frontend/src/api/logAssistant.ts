import { apiClient } from './client'
import type { AskResponse, LogAssistantQuery, SemanticSearchResponse } from '../types'

export const logAssistantApi = {
  search: (query: LogAssistantQuery) =>
    apiClient.post<SemanticSearchResponse>('/log-assistant/search', query).then((r) => r.data),
  ask: (query: LogAssistantQuery) =>
    apiClient.post<AskResponse>('/log-assistant/ask', query).then((r) => r.data),
}
