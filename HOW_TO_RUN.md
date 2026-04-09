# JWT Auth Demo — How to Run & Test

## Pre-requisites
- .NET 8 SDK
- SQL Server (local instance) OR update connection string in appsettings.json

---

## Step 1: Update connection string (if needed)
Open `appsettings.json` and update:
```json
"Default": "Server=YOUR_SERVER;Database=JwtAuthDemo;Trusted_Connection=true;TrustServerCertificate=true;"
```

## Step 2: Run the project
```bash
cd JwtAuthDemo
dotnet run
```
DB is auto-created on first run with 2 seed users.

## Step 3: Open Swagger UI
Navigate to: http://localhost:5000 (or https://localhost:7000)

---

## Test Users (seeded automatically)

| Email              | Password      | Role    | Department |
|--------------------|---------------|---------|------------|
| admin@demo.com     | Admin@123     | Admin   | IT         |
| finance@demo.com   | Finance@123   | User    | Finance    |

---

## How to test in Swagger

### 1. Login
- POST /api/auth/login
- Body: `{ "email": "admin@demo.com", "password": "Admin@123" }`
- Copy the `accessToken` from response

### 2. Authorize in Swagger
- Click "Authorize" button (top right)
- Paste the access token (just the token, no "Bearer " prefix)
- Click Authorize

### 3. Test endpoints
| Endpoint                   | Who can access                  |
|----------------------------|---------------------------------|
| GET /api/products          | Any logged-in user              |
| GET /api/products/public   | Everyone (no login needed)      |
| POST /api/products         | Admin or Manager only           |
| DELETE /api/products/{id}  | Admin only                      |
| GET /api/products/export   | Finance department only         |
| GET /api/products/reports  | Admin or Manager only           |

### 4. Test Refresh Token
- POST /api/auth/refresh (uses HttpOnly Cookie automatically)

### 5. Logout
- POST /api/auth/logout (revokes refresh token, clears cookie)

---

## Key concepts demonstrated in this project

- JWT generation with claims (sub, email, role, department, jti, iat)
- JWT validation (issuer, audience, expiry, signature, clock skew)
- Refresh token rotation with reuse detection
- HttpOnly Secure Cookie for refresh token
- Role-based auth: [Authorize(Roles = "Admin")]
- Policy-based auth: [Authorize(Policy = "FinanceOnly")]
- Reading claims inside controller: User.FindFirst(...)
- Clean 401/403 error responses
- Password hashing with BCrypt
- EF Core with seeded test data
