import uuid
from enum import Enum
from sqlalchemy import Column, String, Enum as SQLAlchemyEnum
from app.config.database import Base

class UserRole(str, Enum):
    admin = "admin"
    fornecedor = "fornecedor"
    atendente = "atendente"
    pai = "pai"
    aluno = "aluno"
    visit = "visit"

class User(Base):
    __tablename__ = "users"

    uuid = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    user_identification = Column(String, unique=True, index=True)
    hashed_passcode = Column(String, nullable=False)

    role = Column(SQLAlchemyEnum(UserRole), default=UserRole.visit, nullable=False)
