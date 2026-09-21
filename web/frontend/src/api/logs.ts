import { apiClient } from './client'
import type { LogSearchFilters, LogSearchResponse } from '../types'

export const logsApi = {
  search: (filters: LogSearchFilters) =>
    apiClient
      .get<LogSearchResponse>('/logs/search', {
        params: Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== undefined && v !== '')),
      })
      .then((r) => r.data),
}
