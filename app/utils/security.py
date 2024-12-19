# app/security.py
from builtins import Exception, ValueError, bool, int, str
import secrets
import bcrypt
from logging import getLogger
from datetime import datetime, timedelta

# Set up logging
logger = getLogger(__name__)

def hash_password(password: str, rounds: int = 12) -> str:

    try:
        salt = bcrypt.gensalt(rounds=rounds)
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), salt)
        return hashed_password.decode('utf-8')
    except Exception as e:
        logger.error("Failed to hash password: %s", e)
        raise ValueError("Failed to hash password") from e

def verify_password(plain_password: str, hashed_password: str) -> bool:

    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception as e:
        logger.error("Error verifying password: %s", e)
        raise ValueError("Authentication process encountered an unexpected error") from e

def generate_verification_token():
    """
    Generates a token for email verification or other purposes like profile upgrade.
    
    """
    return secrets.token_urlsafe(16)  # Generates a secure 16-byte URL-safe token

def generate_profile_upgrade_token(user_id: int) -> str:

    expiration_time = datetime.utcnow() + timedelta(hours=24)  # Token expires in 24 hours
    token_data = {
        "user_id": user_id,
        "exp": expiration_time
    }
    token = secrets.token_urlsafe(16)  # You can customize this based on the desired token format
    # Store the token with the expiration in a secure location (e.g., database or in-memory cache)
    # The token could be tied to the user profile upgrade request
    return token

def verify_profile_upgrade_token(token: str) -> bool:
    """
    Verifies the profile upgrade token.

    """
    # Check the validity of the token (e.g., check expiration, and user association)
    # The token verification logic will depend on how tokens are stored and managed
    try:
        # Example logic: Check if token is valid and has not expired
        # Retrieve token data (e.g., from database or in-memory cache) and verify expiration
        # Placeholder logic:
        token_data = {"user_id": 1, "exp": datetime.utcnow() + timedelta(hours=1)}  # Replace with real token data retrieval
        if datetime.utcnow() > token_data["exp"]:
            return False
        return True
    except Exception as e:
        logger.error("Error verifying profile upgrade token: %s", e)
        return False
