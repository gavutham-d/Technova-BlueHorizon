from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from datetime import datetime, timedelta
from typing import Optional, List
from app.config import settings
from app.database import users_collection, audit_logs_collection
from app.models.schemas import UserCreate, UserLogin, UserResponse, UserInDB, UserRole
import uuid

router = APIRouter(prefix="/auth", tags=["Authentication"])

import bcrypt

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        return False

def get_password_hash(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)
    return encoded_jwt

async def log_audit_action(username: str, role: str, action: str, resource: str, status_str: str, request: Request):
    """
    Compliance logging for Zero Trust posture.
    """
    client_host = request.client.host if request.client else "127.0.0.1"
    audit_doc = {
        "_id": f"audit--{str(uuid.uuid4())}",
        "username": username,
        "role": role,
        "action": action,
        "resource": resource,
        "status": status_str,
        "ip_address": client_host,
        "timestamp": datetime.utcnow()
    }
    await audit_logs_collection.insert_one(audit_doc)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.JWT_SECRET, algorithms=[settings.JWT_ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
        
    user = await users_collection.find_one({"username": username})
    if user is None:
        raise credentials_exception
    return user

class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: dict = Depends(get_current_user)) -> dict:
        if current_user.get("role") not in self.allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Operation not authorized: Insufficient permissions (Zero Trust RBAC)",
            )
        return current_user

# Endpoints
@router.post("/register", response_model=UserResponse)
async def register(user_in: UserCreate, request: Request):
    # Check if username exists
    existing = await users_collection.find_one({"username": user_in.username})
    if existing:
        await log_audit_action("anonymous", "None", "USER_REGISTRATION", user_in.username, "FAILED - DUPLICATE", request)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
        
    # Check if this is the first user (make them admin, otherwise respect requested role or default to read-only)
    count = await users_collection.count_documents({})
    role = UserRole.ADMIN if count == 0 else user_in.role
    
    hashed_pwd = get_password_hash(user_in.password)
    user_doc = {
        "_id": f"user--{str(uuid.uuid4())}",
        "username": user_in.username,
        "email": user_in.email,
        "hashed_password": hashed_pwd,
        "role": role,
        "created_at": datetime.utcnow()
    }
    
    await users_collection.insert_one(user_doc)
    await log_audit_action(user_in.username, role, "USER_REGISTRATION", user_doc["_id"], "SUCCESS", request)
    return user_doc

@router.post("/login")
async def login(credentials: UserLogin, request: Request):
    user = await users_collection.find_one({"username": credentials.username})
    if not user or not verify_password(credentials.password, user["hashed_password"]):
        await log_audit_action(credentials.username, "None", "USER_LOGIN", credentials.username, "FAILED - WRONG CREDENTIALS", request)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token = create_access_token(data={"sub": user["username"]})
    await log_audit_action(user["username"], user["role"], "USER_LOGIN", user["username"], "SUCCESS", request)
    
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "username": user["username"],
        "role": user["role"]
    }

@router.get("/me", response_model=UserResponse)
async def get_me(current_user: dict = Depends(get_current_user)):
    # Simple conversion of DB doc for schema response
    return current_user
