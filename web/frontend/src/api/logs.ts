import { apiClient } from './client'
import type { LogSearchFilters, LogSearchResponse } from '../types'

function cleanParams<T extends object>(filters: T) {
  return Object.fromEntries(Object.entries(filters).filter(([, v]) => v !== undefined && v !== ''))
}

export const logsApi = {
  search: (filters: LogSearchFilters) =>
    apiClient.get<LogSearchResponse>('/logs/search', { params: cleanParams(filters) }).then((r) => r.data),

  // Not paginated -- exports everything matching the current filters (up to
  // the backend's EXPORT_MAX_ROWS cap) as a single file download, rather
  // than the page the user happens to be viewing.
  export: async (filters: Omit<LogSearchFilters, 'limit' | 'offset'>, format: 'csv' | 'xml') => {
    const response = await apiClient.get('/logs/export', {
      params: { ...cleanParams(filters), format },
      responseType: 'blob',
    })
    const disposition = response.headers['content-disposition'] as string | undefined
    const filename = disposition?.match(/filename="?([^"]+)"?/)?.[1] ?? `logs_export.${format}`
    const url = URL.createObjectURL(response.data as Blob)
    const link = document.createElement('a')
    link.href = url
    link.download = filename
    document.body.appendChild(link)
    link.click()
    link.remove()
    URL.revokeObjectURL(url)
    return { truncated: response.headers['x-export-truncated'] === 'true' }
  },
}
