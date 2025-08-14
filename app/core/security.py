import os
import re
from typing import Optional
from datetime import timedelta, datetime, timezone
from app.model.user import User, UserRole
from fastapi import Depends, HTTPException, status, APIRouter
from fastapi.security import OAuth2PasswordBearer
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel
from app.core.database import get_db
from app.config.database import Session

router = APIRouter(prefix="/safe")

# =============================
# Config
# =============================
SECRET_KEY = os.getenv("SECRET_ENV", "secretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7

TOKEN_BLACKLIST = set()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# =============================
# Models
# =============================
class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    user_identification: Optional[str] = None
    role: Optional[str] = None

# =============================
# Password hashing & validation
# =============================
def validate_password_strength(password: str):
    if len(password) < 8:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must be at least 8 characters long")
    if not re.search(r"[A-Z]", password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain an uppercase letter")
    if not re.search(r"\d", password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Password must contain a number")

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

# =============================
# Logout / Revoke Endpoint
# =============================
class LogoutRequest(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None

@router.post("/logout")
def logout(request: LogoutRequest):
    revoke_token(request.access_token)
    if request.refresh_token:
        revoke_token(request.refresh_token)
    return {"msg": "Tokens revoked successfully"}

# =============================
# Refresh Token Endpoint
# =============================
class RefreshTokenRequest(BaseModel):
    refresh_token: str

@router.post("/refresh", response_model=Token)
def refresh_access_token(request: RefreshTokenRequest):
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        if is_token_revoked(request.refresh_token):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token revoked")

        user_identification: str = payload.get("sub")
        role: str = payload.get("role")

        if not user_identification:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token payload")

        # Create new access token
        new_access_token = create_access_token({"sub": user_identification, "role": role})
        return Token(access_token=new_access_token)

    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid refresh token")

# =============================
# JWT creation
# =============================
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.now(tz=timezone.utc) + (
        expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(data: dict) -> str:
    expire = datetime.now(tz=timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    data.update({"exp": expire})
    return jwt.encode(data, SECRET_KEY, algorithm=ALGORITHM)

# =============================
# Token blacklist
# =============================
def revoke_token(token: str):
    TOKEN_BLACKLIST.add(token)

def is_token_revoked(token: str) -> bool:
    return token in TOKEN_BLACKLIST

# =============================
# JWT decoding & user retrieval
# =============================
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_identification: str = payload.get("identification")  # <-- corrected
        role: str = payload.get("role")

        if user_identification is None:
            raise credentials_exception

        # Fetch actual user from DB
        user = db.query(User).filter(User.user_identification == user_identification).first()
        if not user:
            raise credentials_exception

        return user  # return User instance

    except JWTError:
        raise credentials_exception

# =============================
# Example protected route with refresh
# =============================
@router.get("/protected")
async def read_users_me(current_user: User = Depends(get_current_user)):
    return {
        "uuid": current_user.uuid,
        "identification": current_user.user_identification,
        "role": current_user.role.value if isinstance(current_user.role, UserRole) else current_user.role
    }
# =============================
# Role-based access control
# =============================
def require_roles(*allowed_roles: UserRole):
    def role_checker(current_user: User = Depends(get_current_user)):
        user_role = current_user.role
        if isinstance(user_role, UserRole):
            role_value = user_role
        else:
            role_value = UserRole(user_role)  # convert string to enum if needed

        if role_value not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You do not have permission to access this resource"
            )
        return current_user
    return role_checker

@router.get("/admin")
def read_admin_data(current_user=Depends(require_roles(UserRole.admin))):
    return {"msg": "Welcome Admin"}
