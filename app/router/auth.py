from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi import APIRouter, HTTPException, status, Depends
from app.core.database import get_db
from app.core.security import verify_password, create_access_token, create_refresh_token, get_current_user
from app.config.database import Session
from app.model.user import User, UserRole
from pydantic import BaseModel
from typing import Optional, Literal

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/token")
auth = APIRouter()


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

@auth.post("/token", response_model=TokenResponse)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.user_identification == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_passcode):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = {
        "identification": user.user_identification,
        "uuid": user.uuid,
        "role": user.role.value if isinstance(user.role, UserRole) else user.role
    }

    access_token = create_access_token(payload)
    refresh_token = create_refresh_token(payload)

    return TokenResponse(access_token=access_token, refresh_token=refresh_token)


class RoleUpdateRequest(BaseModel):
    new_role: Literal["admin", "fornecedor", "atendente", "pai", "aluno", "visit"]

class TokenData(BaseModel):
    user_identification: Optional[str] = None
    role: Optional[str] = None

# --------------------------
# Temporary Role Change Endpoint
# --------------------------
@auth.put("/test/change_role")
async def change_user_role(
    data: RoleUpdateRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    # Update role
    current_user.role = UserRole(data.new_role)
    db.commit()
    db.refresh(current_user)

    return {"uuid": current_user.uuid, "new_role": current_user.role.value}
