from builtins import Exception
from fastapi import FastAPI, Depends, HTTPException
from starlette.responses import JSONResponse
from starlette.middleware.cors import CORSMiddleware
from app.database import Database
from app.dependencies import get_settings, get_current_user
from app.routers import user_routes
from app.services.jwt_service import decode_token
from app.utils.api_description import getDescription
from app.models.user_model import User

app = FastAPI(
    title="User Management",
    description=getDescription(),
    version="0.0.1",
    contact={
        "name": "API Support",
        "url": "http://www.example.com/support",
        "email": "support@example.com",
    },
    license_info={"name": "MIT", "url": "https://opensource.org/licenses/MIT"},
)

# CORS middleware configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # List of origins that are allowed to access the server, ["*"] allows all
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.on_event("startup")
async def startup_event():
    settings = get_settings()
    Database.initialize(settings.database_url, settings.debug)

@app.exception_handler(Exception)
async def exception_handler(request, exc):
    return JSONResponse(status_code=500, content={"message": "An unexpected error occurred."})

# JWT Authentication Dependency
def get_current_user_from_token(token: str = Depends(get_current_user)):
    """
    Dependency to get the current user based on the JWT token.
    This will be used for protected routes requiring user authentication.
    """
    decoded = decode_token(token)
    if decoded is None:
        raise HTTPException(status_code=401, detail="Invalid or expired token.")
    user = User.get_by_id(decoded["user_id"])
    if user is None:
        raise HTTPException(status_code=404, detail="User not found.")
    return user

@app.post("/profile/upgrade")
async def upgrade_user_profile(user: User = Depends(get_current_user_from_token)):
    """
    Endpoint to upgrade the user's profile to a professional status.
    This requires an authenticated user to upgrade their profile.
    """
    if user.role == "professional":
        raise HTTPException(status_code=400, detail="User is already a professional.")
    user.role = "professional"
    user.save()  # Assuming a method to save the user in your database
    return {"message": "Profile upgraded to professional status."}

app.include_router(user_routes.router)
