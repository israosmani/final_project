from builtins import Exception, dict, str
from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from app.database import Database
from app.utils.template_manager import TemplateManager
from app.services.email_service import EmailService
from app.services.jwt_service import decode_token
from settings.config import Settings
from fastapi import Depends
from app.models.user_model import User  # Import the User model

def get_settings() -> Settings:
    """Return application settings."""
    return Settings()

def get_email_service() -> EmailService:
    template_manager = TemplateManager()
    return EmailService(template_manager=template_manager)

async def get_db() -> AsyncSession:
    """Dependency that provides a database session for each request."""
    async_session_factory = Database.get_session_factory()
    async with async_session_factory() as session:
        try:
            yield session
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

# OAuth2 password bearer for token extraction
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

def get_current_user(token: str = Depends(oauth2_scheme), db: AsyncSession = Depends(get_db)):
    """
    Get the current user from the JWT token.
    Validates the token and fetches the user from the database.
    """
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    # Decode token
    payload = decode_token(token)
    if payload is None:
        raise credentials_exception
    
    # Extract user info from token payload
    user_id: str = payload.get("sub")
    user_role: str = payload.get("role")
    
    if user_id is None or user_role is None:
        raise credentials_exception
    
    # Fetch the user from the database using user_id
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise credentials_exception

    # Optionally, check that the role matches
    if user_role != user.role:
        raise credentials_exception

    return user  # Return the full User object

def require_role(roles: list):
    """
    Dependency that checks if the user has the required role(s).
    This allows flexible role-based access control.
    """
    def role_checker(current_user: User = Depends(get_current_user)):
        if current_user.role not in roles:
            raise HTTPException(status_code=403, detail="Operation not permitted")
        return current_user
    return role_checker
