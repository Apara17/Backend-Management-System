import os
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import jwt
import re
from fastapi import FastAPI, HTTPException, Depends, Header, status
from pydantic import BaseModel, EmailStr, Field, validator
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase
from passlib.context import CryptContext
from bson import ObjectId


#  CONFIGURATION 
class AppConfig:
    """Centralized application configuration"""
    MONGO_URI: str = os.getenv("MONGO_URI", "mongodb://localhost:27017")
    PRIMARY_DB: str = os.getenv("PRIMARY_DB", "enterprise_db")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-change-in-production")
    ALGORITHM: str = os.getenv("ALGORITHM", "HS256")
    TOKEN_LIFETIME: int = int(os.getenv("TOKEN_LIFETIME", "60"))
    PASSWORD_MIN_LENGTH: int = 8
    ORG_NAME_MIN: int = 3
    ORG_NAME_MAX: int = 50


config = AppConfig()


#  DATABASE CONNECTION 
class DatabaseManager:
    """Manages MongoDB connections and database access"""
    
    def __init__(self, uri: str, db_name: str):
        self.client = AsyncIOMotorClient(uri)
        self.primary_database: AsyncIOMotorDatabase = self.client[db_name]
    
    async def close(self):
        """Close database connection"""
        self.client.close()
    
    def get_database(self) -> AsyncIOMotorDatabase:
        """Get primary database instance"""
        return self.primary_database


db_manager = DatabaseManager(config.MONGO_URI, config.PRIMARY_DB)
primary_db = db_manager.get_database()


#  PYDANTIC MODELS 
class AdminRegistrationPayload(BaseModel):
    """Schema for admin registration during organization creation"""
    organization_name: str = Field(..., min_length=config.ORG_NAME_MIN, max_length=config.ORG_NAME_MAX)
    email: EmailStr
    password: str = Field(..., min_length=config.PASSWORD_MIN_LENGTH)


class AdminAuthPayload(BaseModel):
    """Schema for admin login authentication"""
    email: EmailStr
    password: str = Field(..., min_length=config.PASSWORD_MIN_LENGTH)


class OrgUpdatePayload(BaseModel):
    """Schema for updating organization details"""
    organization_name: str = Field(..., min_length=config.ORG_NAME_MIN, max_length=config.ORG_NAME_MAX)
    email: EmailStr
    password: str = Field(..., min_length=config.PASSWORD_MIN_LENGTH)


class OrgDeletePayload(BaseModel):
    """Schema for organization deletion request"""
    organization_name: str = Field(..., min_length=config.ORG_NAME_MIN, max_length=config.ORG_NAME_MAX)


class OrganizationMetadata(BaseModel):
    """Response schema for organization information"""
    id: str
    organization_name: str
    organization_identifier: str
    tenant_collection: str
    admin_email: EmailStr
    
    class Config:
        from_attributes = True


#  SECURITY & HASHING 
class PasswordHandler:
    """Handles password hashing and verification using bcrypt"""
    
    def __init__(self):
        self.context = CryptContext(schemes=["bcrypt"], deprecated="auto")
    
    def hash(self, raw_password: str) -> str:
        """Hash a plain text password"""
        return self.context.hash(raw_password)
    
    def validate(self, raw_password: str, hashed_password: str) -> bool:
        """Verify a plain text password against its hash"""
        return self.context.verify(raw_password, hashed_password)


class TokenManager:
    """Handles JWT token creation and validation"""
    
    def __init__(self, secret: str, algorithm: str, expire_minutes: int):
        self.secret = secret
        self.algorithm = algorithm
        self.expire_minutes = expire_minutes
    
    def generate(self, admin_id: str, org_id: str, admin_email: str) -> str:
        """Generate a JWT token with admin and organization context"""
        expiration_time = datetime.utcnow() + timedelta(minutes=self.expire_minutes)
        token_payload = {
            "admin_id": admin_id,
            "org_id": org_id,
            "email": admin_email,
            "exp": expiration_time
        }
        return jwt.encode(token_payload, self.secret, algorithm=self.algorithm)
    
    def parse(self, token: str) -> Dict[str, Any]:
        """Decode and validate a JWT token"""
        try:
            return jwt.decode(token, self.secret, algorithms=[self.algorithm])
        except jwt.InvalidTokenError as e:
            raise ValueError(f"Token validation failed: {str(e)}")


pwd_handler = PasswordHandler()
token_mgr = TokenManager(config.SECRET_KEY, config.ALGORITHM, config.TOKEN_LIFETIME)


#  UTILITY FUNCTIONS 
def normalize_org_identifier(org_name: str) -> str:
    """
    Convert organization name to a valid identifier (slug).
    Example: "Tech Corp" -> "tech-corp"
    """
    normalized = org_name.lower().strip()
    normalized = re.sub(r'\s+', '-', normalized)
    normalized = re.sub(r'[^a-z0-9-]', '', normalized)
    normalized = re.sub(r'-+', '-', normalized)
    normalized = normalized.strip('-')
    
    if not normalized or not re.match(r'^[a-z0-9]([a-z0-9-]*[a-z0-9])?$', normalized):
        raise ValueError("Organization name produces invalid identifier after normalization")
    
    return normalized


def generate_tenant_collection_name(identifier: str) -> str:
    """
    Generate tenant-specific collection name.
    Example: "tech-corp" -> "tenant_tech_corp"
    """
    return f"tenant_{identifier.replace('-', '_')}"


#  SERVICE LAYER 
class AdminRepository:
    """Data access layer for admin users"""
    
    def __init__(self, database: AsyncIOMotorDatabase):
        self.db = database
        self.collection_name = "admin_accounts"
    
    async def find_by_email(self, email: str) -> Optional[Dict]:
        """Retrieve admin by email address"""
        return await self.db[self.collection_name].find_one({"email": email})
    
    async def find_by_id(self, admin_id: str) -> Optional[Dict]:
        """Retrieve admin by ID"""
        try:
            return await self.db[self.collection_name].find_one({"_id": ObjectId(admin_id)})
        except Exception:
            return None
    
    async def insert(self, admin_data: Dict) -> str:
        """Create new admin account"""
        result = await self.db[self.collection_name].insert_one(admin_data)
        return str(result.inserted_id)
    
    async def delete(self, admin_id: str) -> bool:
        """Delete admin account"""
        result = await self.db[self.collection_name].delete_one({"_id": ObjectId(admin_id)})
        return result.deleted_count > 0


class OrganizationRepository:
    """Data access layer for organizations"""
    
    def __init__(self, database: AsyncIOMotorDatabase):
        self.db = database
        self.collection_name = "org_registry"
    
    async def find_by_identifier(self, identifier: str) -> Optional[Dict]:
        """Retrieve organization by identifier"""
        return await self.db[self.collection_name].find_one({"identifier": identifier})
    
    async def find_by_id(self, org_id: str) -> Optional[Dict]:
        """Retrieve organization by ID"""
        try:
            return await self.db[self.collection_name].find_one({"_id": ObjectId(org_id)})
        except Exception:
            return None
    
    async def insert(self, org_data: Dict) -> str:
        """Create new organization"""
        result = await self.db[self.collection_name].insert_one(org_data)
        return str(result.inserted_id)
    
    async def update(self, org_id: str, updates: Dict) -> bool:
        """Update organization details"""
        result = await self.db[self.collection_name].update_one(
            {"_id": ObjectId(org_id)},
            {"$set": updates}
        )
        return result.modified_count > 0
    
    async def delete(self, org_id: str) -> bool:
        """Delete organization"""
        result = await self.db[self.collection_name].delete_one({"_id": ObjectId(org_id)})
        return result.deleted_count > 0


class TenantDataStore:
    """Manages tenant-specific data collections"""
    
    def __init__(self, database: AsyncIOMotorDatabase):
        self.db = database
    
    async def initialize_collection(self, collection_name: str) -> None:
        """Create and initialize tenant collection with metadata"""
        collection = self.db[collection_name]
        await collection.insert_one({
            "metadata": {
                "created_at": datetime.utcnow(),
                "schema_version": "1.0"
            }
        })
    
    async def migrate_data(self, source_collection: str, destination_collection: str) -> int:
        """Copy all documents from source to destination collection"""
        source = self.db[source_collection]
        destination = self.db[destination_collection]
        
        documents = await source.find({}).to_list(None)
        migrated_count = 0
        
        if documents:
            for doc in documents:
                doc.pop("_id", None)
                await destination.insert_one(doc)
                migrated_count += 1
        
        return migrated_count
    
    async def drop_collection(self, collection_name: str) -> None:
        """Remove tenant collection"""
        await self.db.drop_collection(collection_name)


class AuthenticationService:
    """Handles authentication and authorization logic"""
    
    def __init__(self, admin_repo: AdminRepository, org_repo: OrganizationRepository):
        self.admin_repo = admin_repo
        self.org_repo = org_repo
    
    async def authenticate_admin(self, email: str, password: str) -> Dict[str, Any]:
        """Authenticate admin by email and password, return token payload"""
        admin = await self.admin_repo.find_by_email(email)
        
        if not admin or not pwd_handler.validate(password, admin["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid email or password"
            )
        
        org = await self.org_repo.find_by_id(str(admin["organization_id"]))
        if not org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Associated organization not found"
            )
        
        token = token_mgr.generate(str(admin["_id"]), str(org["_id"]), email)
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "admin_id": str(admin["_id"]),
            "org_id": str(org["_id"])
        }


class OrganizationService:
    """Business logic for organization management"""
    
    def __init__(self, 
                 admin_repo: AdminRepository,
                 org_repo: OrganizationRepository,
                 tenant_store: TenantDataStore):
        self.admin_repo = admin_repo
        self.org_repo = org_repo
        self.tenant_store = tenant_store
    
    async def register_organization(self, 
                                   org_name: str, 
                                   admin_email: str, 
                                   admin_password: str) -> Dict[str, Any]:
        """Create new organization with admin account and tenant collection"""
        
        org_identifier = normalize_org_identifier(org_name)
        
        # Check if organization already exists
        existing = await self.org_repo.find_by_identifier(org_identifier)
        if existing:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Organization '{org_name}' already registered"
            )
        
        # Create admin account
        admin_entry = {
            "email": admin_email,
            "password_hash": pwd_handler.hash(admin_password),
            "created_at": datetime.utcnow()
        }
        admin_id = await self.admin_repo.insert(admin_entry)
        
        # Create organization record
        tenant_collection = generate_tenant_collection_name(org_identifier)
        org_entry = {
            "name": org_name,
            "identifier": org_identifier,
            "tenant_collection": tenant_collection,
            "admin_id": ObjectId(admin_id),
            "created_at": datetime.utcnow(),
            "modified_at": datetime.utcnow()
        }
        org_id = await self.org_repo.insert(org_entry)
        
        # Link admin to organization
        await primary_db["admin_accounts"].update_one(
            {"_id": ObjectId(admin_id)},
            {"$set": {"organization_id": ObjectId(org_id)}}
        )
        
        # Initialize tenant collection
        await self.tenant_store.initialize_collection(tenant_collection)
        
        return {
            "id": org_id,
            "organization_name": org_name,
            "organization_identifier": org_identifier,
            "tenant_collection": tenant_collection,
            "admin_email": admin_email
        }
    
    async def retrieve_organization(self, org_name: str) -> Dict[str, Any]:
        """Fetch organization details by name"""
        org_identifier = normalize_org_identifier(org_name)
        org = await self.org_repo.find_by_identifier(org_identifier)
        
        if not org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Organization '{org_name}' not found"
            )
        
        admin = await self.admin_repo.find_by_id(str(org["admin_id"]))
        
        return {
            "id": str(org["_id"]),
            "organization_name": org["name"],
            "organization_identifier": org["identifier"],
            "tenant_collection": org["tenant_collection"],
            "admin_email": admin["email"] if admin else "unknown"
        }
    
    async def rename_organization(self, 
                                 current_name: str, 
                                 new_name: str, 
                                 admin_email: str,
                                 admin_password: str) -> Dict[str, Any]:
        """Update organization name and tenant collection"""
        
        current_identifier = normalize_org_identifier(current_name)
        new_identifier = normalize_org_identifier(new_name)
        
        # Verify admin credentials
        admin = await self.admin_repo.find_by_email(admin_email)
        if not admin or not pwd_handler.validate(admin_password, admin["password_hash"]):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid admin credentials"
            )
        
        # Get current organization
        org = await self.org_repo.find_by_identifier(current_identifier)
        if not org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Organization '{current_name}' not found"
            )
        
        # Check if new name already exists
        if new_identifier != current_identifier:
            existing = await self.org_repo.find_by_identifier(new_identifier)
            if existing:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"Organization name '{new_name}' already in use"
                )
        
        # Migrate data to new collection
        old_collection = org["tenant_collection"]
        new_collection = generate_tenant_collection_name(new_identifier)
        
        await self.tenant_store.initialize_collection(new_collection)
        migrated = await self.tenant_store.migrate_data(old_collection, new_collection)
        await self.tenant_store.drop_collection(old_collection)
        
        # Update organization record
        update_data = {
            "name": new_name,
            "identifier": new_identifier,
            "tenant_collection": new_collection,
            "modified_at": datetime.utcnow()
        }
        await self.org_repo.update(str(org["_id"]), update_data)
        
        return {
            "message": "Organization updated successfully",
            "previous_collection": old_collection,
            "current_collection": new_collection,
            "documents_migrated": migrated,
            "organization_identifier": new_identifier
        }
    
    async def terminate_organization(self, 
                                    org_name: str, 
                                    requester_admin_id: str) -> Dict[str, str]:
        """Delete organization and associated resources"""
        
        org_identifier = normalize_org_identifier(org_name)
        org = await self.org_repo.find_by_identifier(org_identifier)
        
        if not org:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Organization '{org_name}' not found"
            )
        
        # Authorization check
        if str(org["admin_id"]) != requester_admin_id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You are not authorized to delete this organization"
            )
        
        # Delete tenant collection
        await self.tenant_store.drop_collection(org["tenant_collection"])
        
        # Delete admin account
        await self.admin_repo.delete(str(org["admin_id"]))
        
        # Delete organization record
        await self.org_repo.delete(str(org["_id"]))
        
        return {"message": "Organization and all associated data have been deleted"}


# Initialize repositories and services
admin_repo = AdminRepository(primary_db)
org_repo = OrganizationRepository(primary_db)
tenant_store = TenantDataStore(primary_db)
auth_service = AuthenticationService(admin_repo, org_repo)
org_service = OrganizationService(admin_repo, org_repo, tenant_store)


#  DEPENDENCY INJECTION 
async def extract_admin_context(authorization: str = Header(None)) -> Dict[str, Any]:
    """
    Extract and validate admin context from Authorization header.
    Expected format: "Bearer <token>"
    """
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
            headers={"WWW-Authenticate": "Bearer"}
        )
    
    token_value = authorization.split(" ", 1)[1]
    
    try:
        payload = token_mgr.parse(token_value)
        return payload
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"}
        )


# FASTAPI APPLICATION
app = FastAPI(
    title="Enterprise Organization Management API",
    description="Multi-tenant organization management service with JWT authentication",
    version="1.0.0"
)


@app.on_event("shutdown")
async def shutdown_event():
    """Clean up database connection on application shutdown"""
    await db_manager.close()


#  API ENDPOINTS 

@app.post("/org/create", response_model=OrganizationMetadata)
async def create_organization(payload: AdminRegistrationPayload):
    """
    Create a new organization with admin account and tenant collection.
    
    - **organization_name**: Name of the organization (3-50 characters)
    - **email**: Admin email address
    - **password**: Admin password (minimum 8 characters)
    """
    return await org_service.register_organization(
        org_name=payload.organization_name,
        admin_email=payload.email,
        admin_password=payload.password
    )


@app.get("/org/get", response_model=OrganizationMetadata)
async def get_organization(organization_name: str):
    """
    Retrieve organization details by name.
    
    - **organization_name**: Name of the organization to retrieve
    """
    return await org_service.retrieve_organization(organization_name)


@app.put("/org/update")
async def update_organization(
    payload: OrgUpdatePayload,
    current_admin: Dict[str, Any] = Depends(extract_admin_context)
):
    """
    Update organization name and tenant collection.
    Requires valid JWT authentication.
    
    - **organization_name**: New name for the organization
    - **email**: Admin email (for credential verification)
    - **password**: Admin password (for credential verification)
    """
    return await org_service.rename_organization(
        current_name=payload.organization_name,
        new_name=payload.organization_name,
        admin_email=payload.email,
        admin_password=payload.password
    )


@app.delete("/org/delete")
async def delete_organization(
    payload: OrgDeletePayload,
    current_admin: Dict[str, Any] = Depends(extract_admin_context)
):
    """
    Delete organization and all associated resources.
    Requires valid JWT authentication and authorization.
    
    - **organization_name**: Name of the organization to delete
    """
    return await org_service.terminate_organization(
        org_name=payload.organization_name,
        requester_admin_id=current_admin["admin_id"]
    )


@app.post("/admin/login")
async def login_admin(payload: AdminAuthPayload):
    """
    Authenticate admin and generate JWT token.
    
    - **email**: Admin email address
    - **password**: Admin password
    
    Returns JWT token for authenticated requests.
    """
    return await auth_service.authenticate_admin(
        email=payload.email,
        password=payload.password
    )


# HEALTH CHECK 
@app.get("/health")
async def health_check():
    """Simple health check endpoint"""
    return {"status": "operational", "service": "Organization Management API"}
