import { apiClient } from './client'
import type { Device, ResolutionSummary } from '../types'

export const devicesApi = {
  list: () => apiClient.get<Device[]>('/devices').then((r) => r.data),
  resolutionSummary: () => apiClient.get<ResolutionSummary[]>('/devices/resolution-summary').then((r) => r.data),
}
