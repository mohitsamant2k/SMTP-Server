# SMTP Server Frontend + Backend

This project implements Azure AD authentication using OAuth 2.0 authorization code flow with a private/confidential client.

## Setup

### Backend (Go)

1. Navigate to the Backend directory:

```bash
cd Backend
```

2. Set your Azure AD configuration in main.go:
   - Replace `<YOUR_CLIENT_ID>` with your Azure AD application client ID
   - Replace `<YOUR_CLIENT_SECRET>` with your Azure AD application client secret
   - Replace `<YOUR_TENANT_ID>` with your Azure AD tenant ID

3. Get dependencies and run the server:

```bash
go mod tidy
go run main.go
```

The Go server will start on port 8080.

### Frontend (React)

1. Navigate to the smtp-server-ux directory:

```bash
cd ../smtp-server-ux
```

2. Install dependencies:

```bash
npm install
```

3. Run the development server:

```bash
npm run dev
```

The React app will start on port 5173 by default.

## How It Works

1. When a user visits the app, it checks for authentication by calling `/api/auth/me`
2. If unauthenticated, the user is redirected to the login page
3. Clicking the login button redirects to the backend `/api/auth/login` endpoint
4. The backend initiates the OAuth 2.0 flow and redirects to Azure AD
5. After authentication with Azure AD, the user is redirected back to the backend
6. The backend exchanges the code for tokens and sets an HTTP-only cookie
7. The user is redirected back to the frontend with the session cookie
8. The frontend uses the cookie when making API calls to get the user's information

## Security Features

- Uses HTTP-only cookies for session management
- Implements CORS to allow frontend-backend communication
- Validates OAuth state to prevent CSRF attacks
- All tokens are handled server-side (never exposed to frontend)

## Production Considerations

For production use:
- Use HTTPS for all communications
- Replace the in-memory session store with a persistent database
- Add proper ID token validation and parsing
- Use environment variables for configuration
