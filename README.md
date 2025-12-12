# Enterprise Organization Management API

A robust, production-ready backend service for managing multi-tenant organizations with JWT-based authentication and dynamic database schema management.

##  Overview

This API provides a comprehensive solution for:
- **Organization Creation & Management**: Register, retrieve, update, and delete organizations
- **Multi-Tenant Architecture**: Isolated tenant collections with dynamic collection creation
- **Admin Authentication**: JWT-based token generation and validation
- **Security**: Bcrypt password hashing, secure token management, role-based authorization
- **Data Isolation**: Complete data separation between organizations in MongoDB

##  Architecture

```
┌─────────────────────────────────────────────────┐
│         FastAPI Application Server              │
├─────────────────────────────────────────────────┤
│                                                 │
│  ┌──────────────┐        ┌──────────────────┐  │
│  │  Auth Layer  │        │  Organization    │  │
│  │              │        │  Management      │  │
│  │ - Login      │        │  Layer           │  │
│  │ - Token Gen  │        │                  │  │
│  │ - Validation │        │ - Create Org     │  │
│  └──────────────┘        │ - Retrieve Org   │  │
│                          │ - Update Org     │  │
│                          │ - Delete Org     │  │
│                          └──────────────────┘  │
│                                                 │
├─────────────────────────────────────────────────┤
│         Repository & Service Layer              │
├─────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌────────────┐  ┌──────────┐ │
│  │ AdminRepo   │  │ OrgRepo    │  │TenantDB  │ │
│  │             │  │            │  │Store     │ │
│  └─────────────┘  └────────────┘  └──────────┘ │
│                                                 │
├─────────────────────────────────────────────────┤
│                                                 │
│              MongoDB Database                   │
│  ┌────────────────────────────────────────────┐ │
│  │  Primary Database (enterprise_db)          │ │
│  │                                            │ │
│  │  ┌──────────────────────────────────────┐ │ │
│  │  │ admin_accounts (Master)              │ │ │
│  │  │ - _id, email, password_hash, etc     │ │ │
│  │  └──────────────────────────────────────┘ │ │
│  │                                            │ │
│  │  ┌──────────────────────────────────────┐ │ │
│  │  │ org_registry (Master)                │ │ │
│  │  │ - _id, name, identifier, etc         │ │ │
│  │  └──────────────────────────────────────┘ │ │
│  │                                            │ │
│  │  ┌──────────────────────────────────────┐ │ │
│  │  │ Tenant Collections (Dynamic)         │ │ │
│  │  │ - tenant_tech_corp                   │ │ │
│  │  │ - tenant_finance_inc                 │ │ │
│  │  │ - tenant_startup_labs                │ │ │
│  │  └──────────────────────────────────────┘ │ │
│  └────────────────────────────────────────────┘ │
│                                                 │
└─────────────────────────────────────────────────┘
```

## 🔧 Technology Stack

- **Framework**: FastAPI (async-first Python web framework)
- **Database**: MongoDB (NoSQL document database)
- **Async Driver**: Motor (async MongoDB driver)
- **Authentication**: JWT (JSON Web Tokens)
- **Password Hashing**: Bcrypt
- **Validation**: Pydantic
- **Server**: Uvicorn (ASGI server)

##  Installation

### Prerequisites
- Python 3.8+
- MongoDB 4.0+ (local or cloud)
- pip or poetry

### Setup Steps

1. **Clone the repository**
```bash
git clone https://github.com/yourusername/org-management-backend.git
cd org-management-backend
```

2. **Create virtual environment**
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. **Install dependencies**
```bash
pip install -r requirements.txt
```

4. **Configure environment variables**
```bash
cp .env.example .env
# Edit .env with your MongoDB URI and secrets
```

5. **Start MongoDB**
```bash
# If using local MongoDB
mongod

# Or use MongoDB Atlas (cloud)
# Update MONGO_URI in .env
```

6. **Run the application**
```bash
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

7. **Access API documentation**
- Interactive API docs: http://localhost:8000/docs
- Alternative docs: http://localhost:8000/redoc

##  Environment Configuration

Create a `.env` file in the project root:

```env
# MongoDB Configuration
MONGO_URI=mongodb://localhost:27017
PRIMARY_DB=enterprise_db

# JWT Configuration
SECRET_KEY=your-very-secure-secret-key-change-in-production
ALGORITHM=HS256
TOKEN_LIFETIME=60

# Application Settings
LOG_LEVEL=INFO
```

##  API Endpoints

### 1. Create Organization
**POST** `/org/create`

Creates a new organization with an admin account and dedicated tenant collection.

**Request Body**:
```json
{
  "organization_name": "Tech Innovations Corp",
  "email": "admin@techcorp.com",
  "password": "SecurePassword123"
}
```

**Response** (201):
```json
{
  "id": "507f1f77bcf86cd799439011",
  "organization_name": "Tech Innovations Corp",
  "organization_identifier": "tech-innovations-corp",
  "tenant_collection": "tenant_tech_innovations_corp",
  "admin_email": "admin@techcorp.com"
}
```

**Status Codes**:
- `201 Created`: Organization successfully created
- `400 Bad Request`: Invalid input data
- `409 Conflict`: Organization name already exists

---

### 2. Get Organization
**GET** `/org/get?organization_name=Tech%20Innovations%20Corp`

Retrieves organization details by name.

**Query Parameters**:
- `organization_name` (required): Name of the organization

**Response** (200):
```json
{
  "id": "507f1f77bcf86cd799439011",
  "organization_name": "Tech Innovations Corp",
  "organization_identifier": "tech-innovations-corp",
  "tenant_collection": "tenant_tech_innovations_corp",
  "admin_email": "admin@techcorp.com"
}
```

**Status Codes**:
- `200 OK`: Organization found
- `404 Not Found`: Organization doesn't exist

---

### 3. Update Organization
**PUT** `/org/update`

Updates organization name and migrates data to new tenant collection.
Requires JWT authentication.

**Headers**:
```
Authorization: Bearer <jwt_token>
```

**Request Body**:
```json
{
  "organization_name": "Tech Innovations Corp 2.0",
  "email": "admin@techcorp.com",
  "password": "SecurePassword123"
}
```

**Response** (200):
```json
{
  "message": "Organization updated successfully",
  "previous_collection": "tenant_tech_innovations_corp",
  "current_collection": "tenant_tech_innovations_corp_2_0",
  "documents_migrated": 42,
  "organization_identifier": "tech-innovations-corp-2-0"
}
```

**Status Codes**:
- `200 OK`: Update successful
- `401 Unauthorized`: Invalid credentials
- `403 Forbidden`: Not authorized
- `404 Not Found`: Organization not found
- `409 Conflict`: New name already in use

---

### 4. Delete Organization
**DELETE** `/org/delete`

Permanently deletes organization and all associated data.
Requires JWT authentication and authorization.

**Headers**:
```
Authorization: Bearer <jwt_token>
```

**Request Body**:
```json
{
  "organization_name": "Tech Innovations Corp"
}
```

**Response** (200):
```json
{
  "message": "Organization and all associated data have been deleted"
}
```

**Status Codes**:
- `200 OK`: Deletion successful
- `401 Unauthorized`: Invalid token
- `403 Forbidden`: Not authorized to delete
- `404 Not Found`: Organization not found

---

### 5. Admin Login
**POST** `/admin/login`

Authenticates admin and returns JWT token for authenticated endpoints.

**Request Body**:
```json
{
  "email": "admin@techcorp.com",
  "password": "SecurePassword123"
}
```

**Response** (200):
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "bearer",
  "admin_id": "507f191e810c19729de860ea",
  "org_id": "507f1f77bcf86cd799439011"
}
```

**Status Codes**:
- `200 OK`: Authentication successful
- `401 Unauthorized`: Invalid credentials

---

### 6. Health Check
**GET** `/health`

Simple health check endpoint to verify API is running.

**Response** (200):
```json
{
  "status": "operational",
  "service": "Organization Management API"
}
```

##  Authentication Flow

### JWT Token Structure

The token contains:
- `admin_id`: Identifier of the authenticated admin
- `org_id`: Organization ID the admin belongs to
- `email`: Admin email address
- `exp`: Token expiration time

### Using JWT Token

1. **Login** to get token:
```bash
curl -X POST "http://localhost:8000/admin/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@techcorp.com",
    "password": "SecurePassword123"
  }'
```

2. **Use token** in protected endpoints:
```bash
curl -X PUT "http://localhost:8000/org/update" \
  -H "Authorization: Bearer your_jwt_token_here" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_name": "New Organization Name",
    "email": "admin@techcorp.com",
    "password": "SecurePassword123"
  }'
```

## 📊 Data Model

### Organizations Collection
```javascript
{
  "_id": ObjectId,
  "name": "Tech Innovations Corp",
  "identifier": "tech-innovations-corp",
  "tenant_collection": "tenant_tech_innovations_corp",
  "admin_id": ObjectId,  // Reference to admin
  "created_at": ISODate,
  "modified_at": ISODate
}
```

### Admin Accounts Collection
```javascript
{
  "_id": ObjectId,
  "email": "admin@techcorp.com",
  "password_hash": "$2b$12$...",  // Bcrypt hash
  "organization_id": ObjectId,  // Reference to org
  "created_at": ISODate
}
```

### Tenant Collections (Dynamic)
```javascript
// Collection name: tenant_tech_innovations_corp
{
  "_id": ObjectId,
  "metadata": {
    "created_at": ISODate,
    "schema_version": "1.0"
  }
  // ... organization-specific data
}
```

##  Design Choices & Architecture Decisions

### 1. **Multi-Tenant Isolation via Collections**
- **Decision**: Separate MongoDB collections per tenant instead of single collection with tenant_id
- **Rationale**: 
  - Better query performance (no filtering by tenant_id on every query)
  - Complete data isolation
  - Easy to scale with sharding
  - Aligns with organizational separation
- **Trade-offs**: More collections to manage, but modern MongoDB handles this well

### 2. **Master Database Pattern**
- **Decision**: Separate master database for metadata vs tenant data
- **Rationale**:
  - Centralized organization registry
  - Single source of truth for tenant configuration
  - Easier billing and analytics
- **Alternative**: Could use single database with collections for both

### 3. **Async/Await with Motor**
- **Decision**: Fully async implementation with Motor driver
- **Rationale**:
  - Non-blocking database operations
  - Better resource utilization
  - Handles concurrent requests efficiently
- **Alternative**: Sync PyMongo (simpler but less scalable)

### 4. **Class-Based Services**
- **Decision**: Repository pattern + Service layer
- **Rationale**:
  - Separation of concerns
  - Testability and maintainability
  - Easy to extend or swap implementations
- **Alternative**: Direct database access in routes (less clean)

### 5. **JWT Token with Org Scoping**
- **Decision**: Include both admin_id and org_id in token payload
- **Rationale**:
  - Can validate org ownership without extra DB query
  - Supports future multi-org admin scenarios
  - Self-contained token
- **Alternative**: Just admin_id (would require lookup)

### 6. **Dynamic Collection Naming**
- **Decision**: `tenant_<identifier>` naming pattern
- **Rationale**:
  - Easily identify tenant collections
  - Prevents naming conflicts
  - Clear relationship to organization
- **Alternative**: Could use org_id as collection name (less readable)

##  Testing the API

### Using cURL

```bash
# 1. Create organization
curl -X POST "http://localhost:8000/org/create" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_name": "Acme Corporation",
    "email": "admin@acme.com",
    "password": "MySecurePassword123"
  }'

# 2. Get organization
curl "http://localhost:8000/org/get?organization_name=Acme%20Corporation"

# 3. Login admin
curl -X POST "http://localhost:8000/admin/login" \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@acme.com",
    "password": "MySecurePassword123"
  }'

# 4. Update organization (use token from login)
curl -X PUT "http://localhost:8000/org/update" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_name": "Acme Global Inc",
    "email": "admin@acme.com",
    "password": "MySecurePassword123"
  }'

# 5. Delete organization
curl -X DELETE "http://localhost:8000/org/delete" \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "organization_name": "Acme Global Inc"
  }'
```

### Using Python Requests
```python
import requests

BASE_URL = "http://localhost:8000"

# Create organization
response = requests.post(f"{BASE_URL}/org/create", json={
    "organization_name": "StartUp Labs",
    "email": "founder@startup.com",
    "password": "SecurePass123"
})
org_data = response.json()
print(org_data)

# Login
response = requests.post(f"{BASE_URL}/admin/login", json={
    "email": "founder@startup.com",
    "password": "SecurePass123"
})
token = response.json()["access_token"]

# Update with token
headers = {"Authorization": f"Bearer {token}"}
response = requests.put(f"{BASE_URL}/org/update", 
    json={
        "organization_name": "StartUp Labs 2.0",
        "email": "founder@startup.com",
        "password": "SecurePass123"
    },
    headers=headers
)
print(response.json())
```

##  Scalability Considerations

### Current Implementation
-  Async/await pattern supports high concurrency
-  MongoDB collections per tenant enable parallel queries
-  Stateless design allows horizontal scaling
-  JWT eliminates session storage

### Future Improvements
- Add connection pooling configuration
- Implement MongoDB sharding for very large datasets
- Add caching layer (Redis) for frequently accessed orgs
- Implement rate limiting
- Add comprehensive logging and monitoring
- Database replication for high availability

##  Security Features

- **Password Hashing**: Bcrypt with salt
- **JWT Tokens**: Time-limited access tokens
- **Input Validation**: Pydantic models validate all inputs
- **Authorization**: Admin can only manage their organization
- **HTTPS**: Configure in production deployment
- **Environment Secrets**: Use .env for sensitive data

##  Project Structure

```
org-management-backend/
├── main.py                 # Application entry point
├── requirements.txt        # Python dependencies
├── .env.example           # Environment variables template
├── .gitignore             # Git ignore rules
├── README.md              # This file
└── .github/
    └── workflows/         # CI/CD configurations
```

##  Error Handling

The API returns appropriate HTTP status codes:
- `200 OK`: Successful GET, PUT requests
- `201 Created`: Successful POST (create)
- `400 Bad Request`: Invalid input validation
- `401 Unauthorized`: Missing/invalid authentication
- `403 Forbidden`: Authorized user but not allowed action
- `404 Not Found`: Resource doesn't exist
- `409 Conflict`: Duplicate organization name
- `500 Server Error`: Unexpected server error

All errors include descriptive messages.

##  Support & Contribution

For issues, feature requests, or contributions:
1. Open an issue on GitHub
2. Create a feature branch
3. Submit a pull request

##  License

MIT License - feel free to use this project for learning and commercial purposes.

##  Development Info

- **Author**: Your Name
- **Created**: December 2025
- **Last Updated**: December 12, 2025
- **Python Version**: 3.8+
- **Status**: Production Ready

##  Key Features Implemented

 Multi-tenant organization management
 Dynamic MongoDB collection creation
 Admin authentication with JWT
 Secure password hashing (Bcrypt)
 Data migration on organization rename
 Role-based authorization
 Async/await non-blocking operations
 Comprehensive error handling
 API documentation with Swagger UI
 Clean, modular architecture


