from builtins import str
import pytest
from httpx import AsyncClient
from app.main import app
from app.models.user_model import User, UserRole
from app.utils.nickname_gen import generate_nickname
from app.utils.security import hash_password
from app.services.jwt_service import decode_token

@pytest.mark.asyncio
async def test_create_user_access_denied(async_client, user_token, email_service):
    headers = {"Authorization": f"Bearer {user_token}"}
    user_data = {
        "nickname": generate_nickname(),
        "email": "test@example.com",
        "password": "sS#fdasrongPassword123!",
    }
    response = await async_client.post("/users/", json=user_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_denied(async_client, verified_user, user_token):
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.get(f"/users/{verified_user.id}", headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_retrieve_user_access_allowed(async_client, admin_user, admin_token):
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.get(f"/users/{admin_user.id}", headers=headers)
    assert response.status_code == 200
    assert response.json()["id"] == str(admin_user.id)

# Add the following test cases

@pytest.mark.asyncio
async def test_update_user_nickname(async_client, verified_user, user_token):
    updated_data = {"nickname": "new_nickname"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["nickname"] == updated_data["nickname"]

@pytest.mark.asyncio
async def test_update_user_email(async_client, verified_user, user_token):
    updated_data = {"email": f"updated_{verified_user.id}@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]

@pytest.mark.asyncio
async def test_update_user_profile_access_denied(async_client, other_user, user_token):
    updated_data = {"nickname": "unauthorized_update"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{other_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_profile_invalid_data_access_denied(async_client, user_token, verified_user):
    updated_data = {"email": "newemail@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_update_user_profile_valid_data_access_allowed(async_client, verified_user, user_token):
    updated_data = {"email": "updatedemail@example.com"}
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["email"] == updated_data["email"]

@pytest.mark.asyncio
async def test_list_users_unauthorized_access(async_client, user_token):
    response = await async_client.get("/users/", headers={"Authorization": f"Bearer {user_token}"})
    assert response.status_code == 403

@pytest.mark.asyncio
async def test_delete_user_invalid_id(async_client, admin_token):
    invalid_user_id = "invalid-id"
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await async_client.delete(f"/users/{invalid_user_id}", headers=headers)
    assert response.status_code == 404
    assert "User not found" in response.json().get("detail", "")

@pytest.mark.asyncio
async def test_update_user_no_changes(async_client, verified_user, user_token):
    updated_data = {"nickname": verified_user.nickname}  # No changes to nickname
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 200
    assert response.json()["nickname"] == verified_user.nickname

@pytest.mark.asyncio
async def test_update_user_invalid_field(async_client, verified_user, user_token):
    updated_data = {"invalid_field": "new_value"}  # Invalid field that should not exist
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 400  # Bad request
    assert "detail" in response.json()  # Assuming the API returns an error message

@pytest.mark.asyncio
async def test_update_user_empty_data(async_client, verified_user, user_token):
    updated_data = {}  # No data provided for update
    headers = {"Authorization": f"Bearer {user_token}"}
    response = await async_client.put(f"/users/{verified_user.id}", json=updated_data, headers=headers)
    assert response.status_code == 400  # Bad request, since no data is provided
    assert "detail" in response.json()  # Assuming the API returns an error message

