import { NavLink, Outlet } from 'react-router-dom'
import { useAuth } from '../auth/AuthContext'

export function Layout() {
  const { user, logout } = useAuth()

  return (
    <div className="app-shell">
      <header className="app-header">
        <span className="app-title">Syslog ML Analytics</span>
        <nav className="app-nav">
          <NavLink to="/" end>
            Devices
          </NavLink>
          {user?.role === 'admin' && <NavLink to="/credentials">SNMP Credentials</NavLink>}
        </nav>
        <div className="app-user">
          <span>
            {user?.username} <span className="role-badge">{user?.role}</span>
          </span>
          <button onClick={logout}>Log out</button>
        </div>
      </header>
      <main className="app-content">
        <Outlet />
      </main>
    </div>
  )
}
