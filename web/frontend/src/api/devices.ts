import { apiClient } from './client'
import type { DeviceListResponse, DeviceSearchFilters, ResolutionSummary } from '../types'

export const devicesApi = {
  list: (filters: DeviceSearchFilters, limit: number, offset: number) =>
    apiClient
      .get<DeviceListResponse>('/devices', {
        params: {
          ...Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== undefined && v !== '')),
          limit,
          offset,
        },
      })
      .then((r) => r.data),
  resolutionSummary: () => apiClient.get<ResolutionSummary[]>('/devices/resolution-summary').then((r) => r.data),
}
