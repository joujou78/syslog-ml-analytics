import axios from 'axios'

const TOKEN_KEY = 'syslog_ml_token'

export const tokenStorage = {
  get: () => localStorage.getItem(TOKEN_KEY),
  set: (token: string) => localStorage.setItem(TOKEN_KEY, token),
  clear: () => localStorage.removeItem(TOKEN_KEY),
}

export const apiClient = axios.create({ baseURL: '/api' })

apiClient.interceptors.request.use((config) => {
  const token = tokenStorage.get()
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

// A 401 means the token is missing/expired/invalid — clear it and let the
// AuthContext-driven redirect to /login take over on the next render.
apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      tokenStorage.clear()
    }
    return Promise.reject(error)
  },
)
