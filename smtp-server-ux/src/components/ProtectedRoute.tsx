import React, { useEffect, useState } from 'react'

type Props = {
  children: React.ReactNode
}

export default function ProtectedRoute({ children }: Props) {
  const [status, setStatus] = useState<'loading' | 'authenticated' | 'unauthenticated'>('loading')

  useEffect(() => {
    // Check authentication status on component mount
    const checkAuth = async () => {
      try {
        const backendUrl = import.meta.env.VITE_REACT_APP_BACKEND_URL || ''
        const response = await fetch(`${backendUrl}/api/auth/me`, {
          credentials: 'include', // Important to include cookies
        })

        if (response.ok) {
          setStatus('authenticated')
        } else {
          // If not authenticated, redirect to login
          setStatus('unauthenticated')
          window.location.href = '/login'
        }
      } catch (error) {
        console.error('Authentication check failed:', error)
        setStatus('unauthenticated')
        window.location.href = '/login'
      }
    }

    checkAuth()
  }, [])

  if (status === 'loading') {
    return (
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh',
        flexDirection: 'column'
      }}>
        <div style={{
          border: '4px solid rgba(0, 0, 0, 0.1)',
          borderLeft: '4px solid #0078d4',
          borderRadius: '50%',
          width: '30px',
          height: '30px',
          animation: 'spin 1s linear infinite',
          marginBottom: '16px'
        }}></div>
        <p>Checking authentication...</p>
        <style>{`
          @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
          }
        `}</style>
      </div>
    )
  }

  return <>{children}</>
}
