import React from 'react'
import { useEffect } from 'react'
import { useNavigate } from 'react-router-dom'

export default function Login() {
  const navigate = useNavigate()

  useEffect(() => {
    const checkLogin = async () => {
      try {
        const backendUrl = import.meta.env.VITE_REACT_APP_BACKEND_URL || ''
        const res = await fetch(`${backendUrl}/api/auth/me`, {
          credentials: 'include',
        })
        if (res.ok) {
          navigate('/')
        }
      } catch (err) {
        // Not logged in, do nothing
      }
    }
    checkLogin()
  }, [navigate])

  const handleLogin = () => {
    const backendUrl = import.meta.env.VITE_REACT_APP_BACKEND_URL || ''
    const returnTo = encodeURIComponent(window.location.pathname !== '/login' ? window.location.pathname : '/')
    window.location.href = `${backendUrl}/api/auth/login?returnTo=${returnTo}`
  }

  return (
    <div style={{
      padding: 20,
      maxWidth: '400px',
      margin: '40px auto',
      textAlign: 'center',
      borderRadius: '8px',
      boxShadow: '0 4px 12px rgba(0,0,0,0.1)'
    }}>
      <h2>Sign in to SMTP Server</h2>
      <p style={{color: '#666', marginBottom: '20px'}}>
        You need to authenticate with Azure AD to access this application.
      </p>
      <button 
        onClick={handleLogin}
        style={{
          background: '#0078d4',
          color: 'white',
          border: 'none',
          padding: '10px 20px',
          borderRadius: '4px',
          fontSize: '16px',
          cursor: 'pointer'
        }}
      >
        Sign in with Microsoft
      </button>
    </div>
  )
}
