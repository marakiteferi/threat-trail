import { BrowserRouter, Routes, Route, Link, useLocation, useNavigate } from 'react-router-dom'
import { Shield, ShieldAlert, ShieldCheck, User, LogOut } from 'lucide-react'
import { AuthProvider, useAuth } from './context/AuthContext'
import Dashboard from './pages/Dashboard'
import Investigation from './pages/Investigation'
import Report from './pages/Report'
import Admin from './pages/Admin'
import Login from './pages/Login'
import Register from './pages/Register'
import AdminLogin from './pages/AdminLogin'
import AdminRoute from './components/AdminRoute'
import ProtectedRoute from './components/ProtectedRoute'
import './App.css'

function Header() {
  const loc = useLocation()
  const navigate = useNavigate()
  const { user, logout, isAdmin, isAuthenticated } = useAuth()

  const handleLogout = () => {
    logout()
    navigate('/login')
  }

  return (
    <header className="app-header">
      <Link to="/" className="app-logo-link">
        <span className="app-logo-icon">
          <Shield size={22} className="logo-shield-svg" />
        </span>
        <div>
          <h1 className="app-logo-text">Threat<span className="app-logo-accent">Trail</span></h1>
          <span className="app-logo-sub">SOC Investigation Trainer</span>
        </div>
      </Link>

      <div className="app-header-live">
        <span className="app-live-dot" />
        <span className="app-live-label">LIVE</span>
      </div>

      <nav className="app-nav">
        <Link to="/" className={`app-nav-link ${loc.pathname === '/' ? 'app-nav-active' : ''}`}>
          Dashboard
        </Link>

        {/* ONLY ADMIN can see the Admin Panel link */}
        {isAdmin && (
          <Link
            to="/admin"
            className={`app-nav-link app-nav-admin ${loc.pathname.startsWith('/admin') && loc.pathname !== '/admin/login' ? 'app-nav-active' : ''}`}
          >
            <ShieldAlert size={15} className="nav-admin-icon" />
            <span>Admin Panel</span>
          </Link>
        )}
      </nav>

      {/* Auth Actions on the right */}
      <div className="app-header-auth">
        {isAuthenticated ? (
          <div className="app-user-profile">
            <div className={`user-badge-pill ${isAdmin ? 'user-badge-admin' : 'user-badge-analyst'}`}>
              <span className="user-icon">
                {isAdmin ? <ShieldCheck size={14} /> : <User size={14} />}
              </span>
              <span className="user-name">{user.username}</span>
              <span className="user-role-tag">{isAdmin ? 'Admin' : 'Analyst'}</span>
            </div>
            <button
              onClick={handleLogout}
              className="app-logout-btn"
              title="Sign Out"
            >
              <LogOut size={13} />
              <span>Sign Out</span>
            </button>
          </div>
        ) : (
          <div className="app-guest-actions">
            <Link
              to="/login"
              className={`app-auth-btn btn-login ${loc.pathname === '/login' ? 'auth-btn-active' : ''}`}
            >
              Sign In
            </Link>
            <Link
              to="/register"
              className={`app-auth-btn btn-register ${loc.pathname === '/register' ? 'auth-btn-active' : ''}`}
            >
              Register
            </Link>
          </div>
        )}
      </div>
    </header>
  )
}

function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <div className="app">
          <Header />
          <main className="app-main">
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/admin/login" element={<AdminLogin />} />
              <Route
                path="/admin"
                element={
                  <AdminRoute>
                    <Admin />
                  </AdminRoute>
                }
              />
              <Route
                path="/investigate/:scenarioId"
                element={
                  <ProtectedRoute>
                    <Investigation />
                  </ProtectedRoute>
                }
              />
              <Route
                path="/report/:scenarioId"
                element={
                  <ProtectedRoute>
                    <Report />
                  </ProtectedRoute>
                }
              />
            </Routes>
          </main>
        </div>
      </AuthProvider>
    </BrowserRouter>
  )
}

export default App
