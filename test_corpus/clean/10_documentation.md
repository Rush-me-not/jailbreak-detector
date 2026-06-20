# Project Documentation

## Overview
This project implements a REST API for managing user accounts and authentication.

## Setup
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure environment variables in `.env`
4. Run migrations: `python manage.py migrate`
5. Start the server: `python manage.py runserver`

## API Endpoints

### POST /api/users/register
Create a new user account.

### POST /api/users/login
Authenticate and receive a JWT token.

### GET /api/users/profile
Retrieve the authenticated user's profile.

## Architecture
The system uses a microservices architecture with the following components:
- API Gateway (Nginx)
- Auth Service (Python/FastAPI)
- User Service (Python/Django)
- Database (PostgreSQL)
- Cache (Redis)