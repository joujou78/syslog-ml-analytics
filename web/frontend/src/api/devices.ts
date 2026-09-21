import { apiClient } from './client'
import type { DeviceListResponse, ResolutionSummary } from '../types'

export const devicesApi = {
  list: (limit: number, offset: number) =>
    apiClient.get<DeviceListResponse>('/devices', { params: { limit, offset } }).then((r) => r.data),
  resolutionSummary: () => apiClient.get<ResolutionSummary[]>('/devices/resolution-summary').then((r) => r.data),
}
