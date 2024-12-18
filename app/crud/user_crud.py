from sqlalchemy.orm import Session
from app.models.user_model import User, UserRole
from app.schemas.user_schema import UserCreate, UserUpdate
from uuid import UUID
from typing import Optional, List
from passlib.hash import bcrypt  # Add passlib for password hashing


def create_user(db: Session, user: UserCreate) -> User:
    """
    Create a new user in the database.

    Args:
        db (Session): Database session.
        user (UserCreate): User creation schema.

    Returns:
        User: The newly created user object.
    """
    hashed_password = bcrypt.hash(user.password)  # Hash the password
    db_user = User(
        email=user.email,
        nickname=user.nickname or user.email.split("@")[0],  # Fallback nickname
        first_name=user.first_name,
        last_name=user.last_name,
        bio=user.bio,
        profile_picture_url=user.profile_picture_url,
        linkedin_profile_url=user.linkedin_profile_url,
        github_profile_url=user.github_profile_url,
        role=user.role,
        hashed_password=hashed_password,  # Save hashed password
    )
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user


def update_user(db: Session, user_id: UUID, updates: UserUpdate) -> Optional[User]:
    """
    Update a user's information.

    """
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        return None

    for key, value in updates.dict(exclude_unset=True).items():
        if key == "password":
            value = bcrypt.hash(value)  # Rehash password if it's being updated
        setattr(user, key, value)

    db.commit()
    db.refresh(user)
    return user
