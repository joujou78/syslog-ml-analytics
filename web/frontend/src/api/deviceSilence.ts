import { apiClient } from './client'
import type { DeviceSilence } from '../types'

export const deviceSilenceApi = {
  list: () => apiClient.get<DeviceSilence[]>('/device-silence').then((r) => r.data),
}
