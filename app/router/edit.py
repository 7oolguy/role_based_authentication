from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from typing import Optional
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.model.user import User
from app.core.security import verify_password, hash_password

class UserUpdateRequest(BaseModel):
    user_identification: Optional[str] = None
    user_passcode: Optional[str] = None        # current password for verification
    user_new_passcode: Optional[str] = None    # new password

class UserUpdateResponse(BaseModel):
    uuid: str
    user_identification: str

    class Config:
        from_attributes = True

e = APIRouter()

@e.put("/update/{user_uuid}", response_model=UserUpdateResponse)
async def update_user(user_uuid: str, data: UserUpdateRequest, db: Session = Depends(get_db)):
    # Find user
    user = db.query(User).filter(User.uuid == user_uuid).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Handle password change
    if data.user_new_passcode:
        if not data.user_passcode:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Current password is required to change password"
            )
        # Verify the plain-text password against the stored hash
        if not verify_password(data.user_passcode, user.hashed_passcode):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Current password is incorrect"
            )
        user.user_passcode = hash_password(data.user_new_passcode)

    # Update identification if provided
    if data.user_identification:
        user.user_identification = data.user_identification

    db.commit()
    db.refresh(user)
    return user
