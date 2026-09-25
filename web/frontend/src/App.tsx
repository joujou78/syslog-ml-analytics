import { Route, Routes } from 'react-router-dom'
import { AuthProvider } from './auth/AuthContext'
import { Layout } from './components/Layout'
import { ProtectedRoute } from './components/ProtectedRoute'
import { Alerts } from './pages/Alerts'
import { AnomalySummary } from './pages/AnomalySummary'
import { AnomalyWindows } from './pages/AnomalyWindows'
import { AuditLog } from './pages/AuditLog'
import { Credentials } from './pages/Credentials'
import { Devices } from './pages/Devices'
import { LogAssistant } from './pages/LogAssistant'
import { Logs } from './pages/Logs'
import { Login } from './pages/Login'
import { QueryConsole } from './pages/QueryConsole'
import { Relays } from './pages/Relays'

export default function App() {
  return (
    <AuthProvider>
      <Routes>
        <Route path="/login" element={<Login />} />
        <Route element={<ProtectedRoute />}>
          <Route element={<Layout />}>
            <Route path="/" element={<Devices />} />
            <Route path="/logs" element={<Logs />} />
            <Route path="/log-assistant" element={<LogAssistant />} />
            <Route path="/anomaly-windows" element={<AnomalyWindows />} />
            <Route path="/anomaly-summary" element={<AnomalySummary />} />
            <Route path="/alerts" element={<Alerts />} />
            <Route element={<ProtectedRoute allowedRoles={['admin']} />}>
              <Route path="/credentials" element={<Credentials />} />
              <Route path="/relays" element={<Relays />} />
              <Route path="/query-console" element={<QueryConsole />} />
              <Route path="/audit-log" element={<AuditLog />} />
            </Route>
          </Route>
        </Route>
      </Routes>
    </AuthProvider>
  )
}
