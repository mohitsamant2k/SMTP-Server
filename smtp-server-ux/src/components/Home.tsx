import { useEffect, useState } from 'react'

type User = {
  id: string
  name: string
  email: string
}

export default function Home() {
  const [user, setUser] = useState<User | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    // Fetch user info when component mounts
    const fetchUser = async () => {
      try {
        const backendUrl = import.meta.env.VITE_REACT_APP_BACKEND_URL || ''
        const response = await fetch(`${backendUrl}/api/auth/me`, {
          credentials: 'include', // Important to include cookies
        })

        if (response.ok) {
          const userData = await response.json()
          setUser(userData)
        }
      } catch (error) {
        console.error('Error fetching user data:', error)
      } finally {
        setLoading(false)
      }
    }

    fetchUser()
  }, [])

  const handleLogout = () => {
    const backendUrl = import.meta.env.VITE_REACT_APP_BACKEND_URL || ''
    // Call logout endpoint
    fetch(`${backendUrl}/api/auth/logout`, {
      method: 'POST',
      credentials: 'include',
    }).then(() => {
      // Redirect to login page after logout
      window.location.href = '/login'
    })
  }

  if (loading) {
    return <div>Loading user data...</div>
  }

  return (
    <div style={{ padding: 20, maxWidth: '800px', margin: '0 auto' }}>
      <div style={{ 
        display: 'flex', 
        justifyContent: 'space-between',
        alignItems: 'center',
        marginBottom: '20px',
        padding: '15px',
        background: '#f5f5f5',
        borderRadius: '8px'
      }}>
        <div>
          <h1>Welcome to SMTP Server</h1>
          {user && (
            <p>
              Signed in as <strong>{user.name}</strong> ({user.email})
            </p>
          )}
        </div>
        <button 
          onClick={handleLogout}
          style={{
            background: '#e0e0e0',
            border: 'none',
            padding: '8px 16px',
            borderRadius: '4px',
            cursor: 'pointer'
          }}
        >
          Sign Out
        </button>
      </div>

      <div style={{ background: 'white', padding: '20px', borderRadius: '8px', boxShadow: '0 2px 8px rgba(0,0,0,0.1)' }}>
        <h2>Your Profile</h2>
        {user ? (
          <div>
            <p><strong>User ID:</strong> {user.id}</p>
            <p><strong>Name:</strong> {user.name}</p>
            <p><strong>Email:</strong> {user.email}</p>

            <div style={{ marginTop: '20px' }}>
              <h3>Raw User Data</h3>
              <pre style={{ background: '#f5f5f5', padding: '10px', borderRadius: '4px', overflow: 'auto' }}>
                {JSON.stringify(user, null, 2)}
              </pre>
            </div>
          </div>
        ) : (
          <p>Could not load user data.</p>
        )}
      </div>
    </div>
  )
}
