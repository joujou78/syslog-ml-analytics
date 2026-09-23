import { apiClient } from './client'
import type { RelaySourceIp, RelaySourceIpInput } from '../types'

export const relaysApi = {
  list: () => apiClient.get<RelaySourceIp[]>('/relays').then((r) => r.data),
  create: (payload: RelaySourceIpInput) => apiClient.post<RelaySourceIp>('/relays', payload).then((r) => r.data),
  remove: (id: string) => apiClient.delete(`/relays/${id}`),
}
