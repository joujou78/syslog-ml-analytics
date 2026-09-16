import { apiClient } from './client'
import type { Credential, CredentialInput } from '../types'

export const credentialsApi = {
  list: () => apiClient.get<Credential[]>('/credentials').then((r) => r.data),
  create: (payload: CredentialInput) => apiClient.post<Credential>('/credentials', payload).then((r) => r.data),
  update: (id: string, payload: CredentialInput) =>
    apiClient.put<Credential>(`/credentials/${id}`, payload).then((r) => r.data),
  remove: (id: string) => apiClient.delete(`/credentials/${id}`),
}
