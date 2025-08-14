from fastapi import APIRouter, HTTPException, status, Depends
from pydantic import BaseModel
from app.service.generator import get_guaranteed_unique_uuid
from app.model.user import User, UserRole
from app.core.security import validate_password_strength, hash_password
from app.core.database import get_db
from app.config.database import Session

class UserCreateData(BaseModel):
    user_identification: str
    user_passcode: str

class UserInDB(BaseModel):
    uuid: str
    user_identification: str
    hashed_passcode: str

class UserResponse(BaseModel):
    uuid: str
    user_identification: str

c = APIRouter()

@c.post("/create_user", response_model=UserResponse)
async def create_new_user(user_data: UserCreateData, db: Session = Depends(get_db)):
    """
    Creates a new user in the database with a hashed password.
    """

    # Check if user already exists
    existing_user = db.query(User).filter(User.user_identification == user_data.user_identification).first()
    if existing_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User identification already exists")

    # Validate password strength
    validate_password_strength(user_data.user_passcode)

    # Create new user
    new_uuid = get_guaranteed_unique_uuid()
    hashed_passcode = hash_password(user_data.user_passcode)

    new_user = User(
        uuid=new_uuid,
        user_identification=user_data.user_identification,
        hashed_passcode=hashed_passcode,
        role=UserRole.visit
    )

    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    return UserResponse(
        uuid=str(new_user.uuid),
        user_identification=new_user.user_identification
    )
