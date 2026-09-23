import { apiClient } from './client'
import type { QueryResult } from '../types'

export const queryConsoleApi = {
  execute: (query: string) =>
    apiClient.post<QueryResult>('/query-console/execute', { query }).then((r) => r.data),
}
