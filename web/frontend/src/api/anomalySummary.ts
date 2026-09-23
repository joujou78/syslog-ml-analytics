import { apiClient } from './client'
import type { DeviceAnomalySummaryRow, VendorAnomalySummaryRow } from '../types'

export const anomalySummaryApi = {
  devices: () => apiClient.get<DeviceAnomalySummaryRow[]>('/anomaly-summary/devices').then((r) => r.data),
  vendors: () => apiClient.get<VendorAnomalySummaryRow[]>('/anomaly-summary/vendors').then((r) => r.data),

  acknowledge: (sourceIp: string, anomalyReason: string, note: string | undefined) =>
    apiClient.post(`/anomaly-summary/devices/${encodeURIComponent(sourceIp)}/${encodeURIComponent(anomalyReason)}/acknowledge`, {
      note: note || undefined,
    }),

  unacknowledge: (sourceIp: string, anomalyReason: string) =>
    apiClient.delete(`/anomaly-summary/devices/${encodeURIComponent(sourceIp)}/${encodeURIComponent(anomalyReason)}/acknowledge`),

  export: async (groupBy: 'device' | 'vendor', format: 'csv' | 'xml') => {
    const response = await apiClient.get('/anomaly-summary/export', {
      params: { group_by: groupBy, format },
      responseType: 'blob',
    })
    const disposition = response.headers['content-disposition'] as string | undefined
    const filename = disposition?.match(/filename="?([^"]+)"?/)?.[1] ?? `anomaly_summary_${groupBy}.${format}`
    const url = URL.createObjectURL(response.data as Blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
  },
}
