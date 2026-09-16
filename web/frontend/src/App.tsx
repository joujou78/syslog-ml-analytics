import { Route, Routes } from 'react-router-dom'
import { AuthProvider } from './auth/AuthContext'
import { Layout } from './components/Layout'
import { ProtectedRoute } from './components/ProtectedRoute'
import { Credentials } from './pages/Credentials'
import { Devices } from './pages/Devices'
import { Login } from './pages/Login'

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<Layout />}>
            <Route path="/" element={<Devices />} />
            <Route element={<ProtectedRoute allowedRoles={['admin']} />}>
              <Route path="/credentials" element={<Credentials />} />
            </Route>
          </Route>
        </Route>
      </Routes>
    </AuthProvider>
  )
}
