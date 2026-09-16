import { createContext, useContext, useEffect, useState, type ReactNode } from 'react'
import { apiClient, tokenStorage } from '../api/client'
import type { User } from '../types'

interface AuthContextValue {
  user: User | null
  loading: boolean
  login: (username: string, password: string) => Promise<void>
  logout: () => void
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined)

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  const fetchCurrentUser = async () => {
    if (!tokenStorage.get()) {
      setUser(null)
      setLoading(false)
      return
    }
    try {
      const response = await apiClient.get<User>('/auth/me')
      setUser(response.data)
    } catch {
      tokenStorage.clear()
      setUser(null)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetchCurrentUser()
  }, [])

  const login = async (username: string, password: string) => {
    const form = new URLSearchParams()
    form.set('username', username)
    form.set('password', password)
    const response = await apiClient.post<{ access_token: string }>('/auth/login', form, {
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    })
    tokenStorage.set(response.data.access_token)
    await fetchCurrentUser()
  }

  const logout = () => {
    tokenStorage.clear()
    setUser(null)
  }

  return <AuthContext.Provider value={{ user, loading, login, logout }}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const ctx = useContext(AuthContext)
  if (!ctx) throw new Error('useAuth must be used within AuthProvider')
  return ctx
}
