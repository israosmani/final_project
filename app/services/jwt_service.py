# app/services/jwt_service.py
from builtins import dict, str
import jwt
from datetime import datetime, timedelta
from settings.config import settings

def create_access_token(*, data: dict, expires_delta: timedelta = None):
    """
    Create an access token with user data, including profile information like role and status.
    
    :param data: User data, including role and status (if applicable).
    :param expires_delta: Optional expiration time for the token.
    :return: Encoded JWT token.
    """
    to_encode = data.copy()

    # Ensure role is in uppercase
    if 'role' in to_encode:
        to_encode['role'] = to_encode['role'].upper()

    # Handle user status (e.g., 'professional')
    if 'status' in to_encode:
        to_encode['status'] = to_encode['status'].upper()

    # Set token expiration time
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=settings.access_token_expire_minutes))
    to_encode.update({"exp": expire})
    
    # Encode JWT token
    encoded_jwt = jwt.encode(to_encode, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)
    return encoded_jwt

def decode_token(token: str):
    """
    Decode the JWT token and extract user data.
    
    :param token: JWT token to decode.
    :return: Decoded data (if valid), None otherwise.
    """
    try:
        # Decode the JWT and check for expiration
        decoded = jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
        return decoded
    except jwt.PyJWTError:
        return None

def is_user_admin(decoded_token: dict) -> bool:
    """
    Check if the decoded JWT token belongs to an admin user.
    
    :param decoded_token: The decoded JWT token.
    :return: True if user is admin, False otherwise.
    """
    return decoded_token.get('role') == 'ADMIN'

def is_user_professional(decoded_token: dict) -> bool:
    """
    Check if the decoded JWT token indicates the user is a professional.
    
    :param decoded_token: The decoded JWT token.
    :return: True if user is a professional, False otherwise.
    """
    return decoded_token.get('status') == 'PROFESSIONAL'
