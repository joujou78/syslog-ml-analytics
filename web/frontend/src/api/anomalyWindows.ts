import { apiClient } from './client'
import type { AnomalyWindowFilters, AnomalyWindowListResponse } from '../types'

export const anomalyWindowsApi = {
  list: (filters: AnomalyWindowFilters, limit: number, offset: number) =>
    apiClient
      .get<AnomalyWindowListResponse>('/anomaly-windows', {
        params: {
          ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== undefined && v !== '')),
          limit,
          offset,
        },
      })
      .then((r) => r.data),
}
