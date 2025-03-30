import pytest
from fastapi.testclient import TestClient
from unittest.mock import patch, MagicMock, AsyncMock
from datetime import datetime, timedelta, timezone
from fastapi import Depends, HTTPException, status
from app.main import app, oauth2_scheme, remove_expired_urls, reload_data_into_redis
from app.models import db, User, URL
import pytz

client = TestClient(app)

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    user = User.get_or_none(User.username == token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or missing token"
        )
    return user


@pytest.fixture(scope="module", autouse=True)
def setup_teardown_db():
    if not db.is_closed():
        db.close()
    db.bind([User, URL], bind_refs=False, bind_backrefs=False)
    db.connect()
    db.create_tables([User, URL])
    yield
    db.drop_tables([User, URL])
    db.close()


def override_get_current_user():
    user = MagicMock()
    user.username = "testuser"
    return user

app.dependency_overrides[get_current_user] = override_get_current_user

@pytest.mark.usefixtures("setup_teardown_db")
def test_register_new_user():
    response = client.post("/register", json={"username": "newuser", "password": "newpassword"})
    assert response.status_code == 200
    assert response.json() == {"msg": "User registered successfully"}
    response = client.post("/register", json={"username": "newuser", "password": "newpassword"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Username already registered"}


@pytest.mark.parametrize("username, password, expected_status", [
    ("testuser", "correctpassword", 200),
    ("wronguser", "wrongpassword", 400),
])
def test_login(username, password, expected_status):
    with patch('app.models.User.get') as mock_get:
        if expected_status == 200:
            mock_user_instance = MagicMock()
            mock_get.return_value = mock_user_instance
            mock_user_instance.verify_password.return_value = True
        else:
            mock_get.side_effect = User.DoesNotExist
        response = client.post(
            "/token",
            data={"username": username, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        assert response.status_code == expected_status


@pytest.mark.usefixtures("setup_teardown_db")
@patch('app.main.redis_client', new_callable=AsyncMock)
def test_create_short_url(mock_redis_client):
    mock_redis_client.exists.return_value = False
    response = client.post("/links/shorten", json={"original_url": "http://example.com"})
    assert response.status_code == 200
    assert "short_url" in response.json()


@patch('app.main.redis_client', new_callable=AsyncMock)
def test_create_short_url_custom_alias_exists(mock_redis_client):
    mock_redis_client.exists.side_effect = lambda key: key == "url:custom123"
    client.post("/links/shorten", json={"original_url": "http://example.com", "custom_alias": "custom123"})
    response = client.post("/links/shorten", json={"original_url": "http://example.com", "custom_alias": "custom123"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Alias already exists"}


@pytest.mark.parametrize("short_code, redis_exists, db_exists, expected_status", [
    ("abc123", True, True, 307),
    ("abc123", False, False, 404),
    ("abc123", True, False, 307),
    ("abc123", False, True, 307),
])

@patch('app.main.redis_client', new_callable=AsyncMock)
def test_redirect_to_url(mock_redis_client, short_code, redis_exists, db_exists, expected_status):
    mock_redis_client.get.return_value = "http://example.com" if redis_exists else None
    with patch('app.models.URL.get_or_none') as mock_get_or_none:
        mock_get_or_none.return_value = MagicMock(original_url="http://example.com") if db_exists else None
        response = client.get(f"/{short_code}", follow_redirects=False)
        assert response.status_code == expected_status
        if expected_status == 307:
            assert response.headers["location"] == "http://example.com"


@pytest.mark.usefixtures("setup_teardown_db")
@patch('app.main.redis_client', new_callable=AsyncMock)
def test_update_url_success(mock_redis_client):
    with patch('app.models.URL.get_or_none') as mock_get_or_none:
        mock_url_instance = mock_get_or_none.return_value
        mock_url_instance.owner = MagicMock(username="testuser")
        response = client.put("/links/short123", json={"original_url": "http://newexample.com"}, headers={"Authorization": "Bearer testuser"})
        assert response.status_code == 200
        assert response.json() == {"msg": "URL updated successfully"}


@pytest.mark.usefixtures("setup_teardown_db")
def test_update_url_fail_no_permission():
    with patch('app.models.URL.get_or_none') as mock_get_or_none:
        mock_get_or_none.return_value = None
        response = client.put("/links/short123", json={"original_url": "http://example.com"}, headers={"Authorization": "Bearer fakeuser"})
        assert response.status_code == 403
        assert response.json() == {"detail": "Operation not allowed"}


@pytest.mark.usefixtures("setup_teardown_db")
@patch('app.main.redis_client', new_callable=AsyncMock)
def test_delete_url_success(mock_redis_client):
    with patch('app.models.URL.get_or_none') as mock_get_or_none:
        mock_url_instance = mock_get_or_none.return_value
        mock_url_instance.owner = MagicMock(username="testuser")
        response = client.delete("/links/short123", headers={"Authorization": "Bearer testuser"})
        assert response.status_code == 200
        assert response.json() == {"msg": "URL deleted successfully"}


@pytest.mark.usefixtures("setup_teardown_db")
def test_delete_url_fail_no_permission():
    with patch('app.models.URL.get_or_none') as mock_get_or_none:
        mock_get_or_none.return_value = None
        response = client.delete("/links/short123", headers={"Authorization": "Bearer fakeuser"})
        assert response.status_code == 403
        assert response.json() == {"detail": "Operation not allowed"}

@pytest.mark.parametrize("short_code, expected_status", [
    ("short123", 200),
    ("nonexistent", 404),
])

def test_get_url_stats(short_code, expected_status):
    with patch('app.models.URL.get_or_none') as mock_get_or_none:
        if expected_status == 404:
            mock_get_or_none.return_value = None
        else:
            mock_url_instance = mock_get_or_none.return_value
            mock_url_instance.original_url = "http://example.com"
            mock_url_instance.clicks = 5
        response = client.get(f"/links/{short_code}/stats")
        assert response.status_code == expected_status
        if expected_status == 200:
            assert response.json().get("original_url") == "http://example.com"
            assert response.json().get("clicks") == 5


@patch('app.main.templates')
def test_root_template(mock_templates):
    mock_template_response = MagicMock()
    mock_templates.TemplateResponse.return_value = mock_template_response
    response = client.get("/")
    assert response.status_code == 200


@patch('app.main.redis_client', new_callable=AsyncMock)
@patch('app.main.templates')
def test_admin_template(mock_templates, mock_redis_client):
    mock_template_response = MagicMock()
    mock_templates.TemplateResponse.return_value = mock_template_response
    mock_templates.TemplateResponse.return_value.status_code = 200
    mock_redis_client.dbsize.return_value = 1
    response = client.get("/admin/")
    assert response.status_code == 200


@patch('app.models.URL.select')
def test_search_links(mock_select):
    mock_url_instance1 = MagicMock(original_url="http://example.com", short_code="abc123")
    mock_url_instance2 = MagicMock(original_url="http://example.com", short_code="xyz789")
    mock_query = MagicMock()
    mock_query.where.return_value = [mock_url_instance1, mock_url_instance2]
    mock_select.return_value = mock_query
    response = client.get("/links/search", params={"original_url": "http://example.com"})
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, list)
    assert len(data) == 2


@patch('app.models.URL.select')
def test_search_links_no_result(mock_select):
    mock_query = MagicMock()
    mock_query.where.return_value = []
    mock_select.return_value = mock_query
    response = client.get("/links/search", params={"original_url": "http://example.com"})
    assert response.status_code == 200
    assert response.json() == []


@pytest.mark.usefixtures("setup_teardown_db")
@patch('app.main.redis_client', new_callable=AsyncMock)
@patch('app.models.URL.select')
async def test_reload_data_into_redis(mock_select, mock_redis_client):
    mock_url_instance = MagicMock(spec=URL)
    mock_url_instance.original_url = "http://example.com"
    mock_url_instance.short_code = "abc123"
    mock_url_instance.expires_at = datetime.now(pytz.utc) + timedelta(days=1)
    mock_select.return_value = [mock_url_instance]
    await reload_data_into_redis()
    mock_redis_client.delete.assert_called()
    mock_redis_client.set.assert_awaited_once_with(
        "url:abc123", "http://example.com",
        ex=int((mock_url_instance.expires_at - datetime.now(pytz.utc)).total_seconds())
    )


@pytest.mark.usefixtures("setup_teardown_db")
def test_get_current_user_invalid_token():
    response = client.get("/links/user", headers={"Authorization": "Bearer invalidtoken"})
    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid or missing token"}


def test_register_duplicate_user():
    with patch('app.models.User.get_or_none') as mock_get_or_none:
        mock_get_or_none.return_value = MagicMock(username="newuser")
        response = client.post("/register", json={"username": "newuser", "password": "newpassword"})
        assert response.status_code == 400
        assert response.json() == {"detail": "Username already registered"}


@pytest.mark.usefixtures("setup_teardown_db")
@patch('app.main.redis_client', new_callable=AsyncMock)
def test_create_short_url_no_auth(mock_redis_client):
    mock_redis_client.exists.return_value = False
    response = client.post("/links/shorten", json={"original_url": "http://example.com"}, headers={"Authorization": ""})
    assert response.status_code == 200
    assert "short_url" in response.json()


@pytest.mark.parametrize("short_code, reveal, expected_response", [
    ("short123", True, {"original_url": "http://example.com"}),
    ("short123", False, 307),
])

@patch('app.main.redis_client', new_callable=AsyncMock)
def test_redirect_to_url_with_reveal(mock_redis_client, short_code, reveal, expected_response):
    mock_redis_client.get.return_value = "http://example.com"
    response = client.get(f"/{short_code}?reveal={str(reveal).lower()}", follow_redirects=False)
    if reveal:
        assert response.status_code == 200
        assert response.json() == expected_response
    else:
        assert response.status_code == expected_response
        if expected_response == 307:
            assert response.headers["location"] == "http://example.com"


@pytest.mark.parametrize("expires_at, expected_expires_at_delta", [
    (None, timedelta(days=7)),
    (datetime.now(timezone.utc) + timedelta(days=10), timedelta(days=10)),
])

def test_url_create_model_default_expires_at(expires_at, expected_expires_at_delta):
    from app.main import URLCreate
    url_create = URLCreate(original_url="http://example.com", expires_at=expires_at)
    expected_expires_at = (datetime.now(timezone.utc) + expected_expires_at_delta
                           if expires_at is None else expires_at)
    delta = timedelta(seconds=1)
    assert abs(url_create.expires_at - expected_expires_at) <= delta


@pytest.mark.usefixtures("setup_teardown_db")
@patch('app.models.URL.select')
@patch('app.main.redis_client', new_callable=AsyncMock)
async def test_remove_expired_urls(mock_redis_client, mock_select):
    mock_expired_url = MagicMock()
    mock_expired_url.short_code = "expired_short"
    mock_expired_url.is_expired = True
    mock_expired_url.delete_instance = AsyncMock()

    class MockQuery:
        def where(self, *args, **kwargs):
            return [mock_expired_url]

    mock_select.return_value = MockQuery()
    await remove_expired_urls()
    await mock_expired_url.delete_instance()
    mock_redis_client.delete.assert_awaited_once_with(f"url:{mock_expired_url.short_code}")


@pytest.mark.parametrize("username, password, expected_status", [
    ("testuser", "correctpassword", 200),
    ("wronguser", "wrongpassword", 400),
    ("testuser", "wrongpassword", 400),
])
def test_login_additional(username, password, expected_status):
    with patch('app.models.User.get') as mock_get:
        if expected_status == 200:
            mock_user_instance = MagicMock()
            mock_get.return_value = mock_user_instance
            mock_user_instance.verify_password.return_value = password == "correctpassword"
        else:
            mock_get.side_effect = User.DoesNotExist
        response = client.post(
            "/token",
            data={"username": username, "password": password},
            headers={"Content-Type": "application/x-www-form-urlencoded"}
        )
        assert response.status_code == expected_status


@pytest.mark.usefixtures("setup_teardown_db")
def test_create_short_url_custom_alias_db_exists():
    User.create(username="testuser", password_hash="hashedpassword")
    URL.create(original_url="http://example.com", short_code="custom123", owner=1)
    response = client.post("/links/shorten", json={"original_url": "http://example.com", "custom_alias": "custom123"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Alias already exists"}


@pytest.mark.usefixtures("setup_teardown_db")
@patch('app.main.redis_client', new_callable=AsyncMock)
def test_update_url_no_change_alias(mock_redis_client):
    with patch('app.models.URL.get_or_none') as mock_get_or_none:
        mock_url_instance = mock_get_or_none.return_value
        mock_url_instance.owner = MagicMock(username="testuser")
        mock_url_instance.original_url = "http://oldexample.com"
        mock_url_instance.custom_alias = "existingalias"
        response = client.put("/links/existingalias", json={"original_url": "http://newexample.com"}, headers={"Authorization": "Bearer testuser"})
        assert response.status_code == 200
        assert response.json() == {"msg": "URL updated successfully"}


@pytest.fixture
def clean_database():
    User.delete().execute()
    URL.delete().execute()


def test_get_user_links_valid_user(clean_database):
    user = User.create(username="testuser_unique", password_hash="hashedpassword")
    link1 = URL.create(original_url="http://example1.com", short_code="code1", owner=user)
    link2 = URL.create(original_url="http://example2.com", short_code="code2", owner=user)
    with patch('app.main.User.get_or_none') as mock_get_user:
        mock_get_user.return_value = user
        response = client.get("/links/user", headers={"Authorization": "Bearer testuser_unique"})
        assert response.status_code == 200
        data = response.json()
        assert "links" in data
        assert isinstance(data["links"], list)
        assert len(data["links"]) == 2
        assert any(link["original_url"] == "http://example1.com" for link in data["links"])
        assert any(link["original_url"] == "http://example2.com" for link in data["links"])
        assert any(link["short_code"] == "code1" for link in data["links"])
        assert any(link["short_code"] == "code2" for link in data["links"])


def test_login_invalid_password():
    mock_user = MagicMock()
    mock_user.username = "testuser"
    mock_user.verify_password.return_value = False
    with patch('app.main.User.get') as mock_get_user:
        mock_get_user.return_value = mock_user
        response = client.post(
            "/token",
            data={"username": "testuser", "password": "wrongpassword"},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        assert response.status_code == 400
        assert response.json() == {"detail": "Invalid username or password"}


@pytest.mark.asyncio
async def test_lifespan_exception():
    from app.main import lifespan
    from fastapi import FastAPI
    app = FastAPI()
    with patch('app.main.reload_data_into_redis', new_callable=AsyncMock) as mock_reload, \
         patch('app.main.remove_expired_urls', new_callable=AsyncMock) as mock_remove:
        mock_reload.side_effect = Exception("Test exception")
        async with lifespan(app):
            mock_reload.assert_awaited_once()
            mock_remove.assert_awaited_once()
