# Building Secure JWT Authentication in Gin with PostgreSQL

Authentication service built with **Gin (Go)**, **JWT** for secure token-based
authentication, and **PostgreSQL** for persistence. Ideal starting point for
building scalable APIs and microservices.

---

## 📖 Features

- User registration, login and logout
- JWT-based authentication
- Password hashing with bcrypt
- PostgreSQL integration
- Environment-based configuration

---

## ⚙️ Setup

### 1. Clone the repo

```bash
git clone https://github.com/nilimdaimari/gin-auth-jwt-postgresql.git
cd gin-auth-jwt-postgresql
```

## Database Setup

## Database Schema

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Optional: Create an index on email for faster lookups
CREATE INDEX idx_users_email ON users(email);
```

## Run the server

go run ./cmd\
or\
go run .

## Build the app

go build -o myapp ./cmd/main.go

## 🔑 API Endpoints

### Public Routes

- **POST** `/api/v1/register` – Register a new user
- **POST** `/api/v1/login` – Login and get a JWT

### Protected Routes (JWT required)

- **POST** `/api/v1/refresh-token` – Refresh access token
- **POST** `/api/v1/logout` – Logout the current user
- **GET** `/api/v1/profile` – Get the authenticated user profile

# 📌 Notes

- Do not commit .env with real secrets. Add it to .gitignore.
- Use HTTPS in production.
- Rotate and protect your JWT_SECRET.
