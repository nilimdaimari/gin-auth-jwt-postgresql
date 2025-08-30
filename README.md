# Building Secure JWT Authentication in Gin with PostgreSQL

A boilerplate authentication service built with **Gin (Go)**, **JWT** for secure
token-based authentication, and **PostgreSQL** for persistence.\
Ideal starting point for building scalable APIs and microservices.

---

## 📖 Features

- User registration and login
- JWT-based authentication
- Password hashing with bcrypt
- Role-based authorization
- PostgreSQL integration
- Environment-based configuration

---

## ⚙️ Setup

### 1. Clone the repo

```bash
git clone https://github.com/your-username/gin-auth-jwt-postgresql.git
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

## Run the server
go run ./cmd
 or
go run .

## 🔑 API Endpoints

POST /auth/register – Register new user
POST /auth/login – Login and get JWT
GET /auth/profile – Get user profile (JWT required)

# 📌 Notes

- Do not commit .env with real secrets. Add it to .gitignore.
- Use HTTPS in production.
- Rotate and protect your JWT_SECRET.
```
