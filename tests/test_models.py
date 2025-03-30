import pytest
from fastapi.testclient import TestClient
from datetime import datetime, timedelta, timezone
from app.main import app
from app.models import db, User, URL
from passlib.hash import bcrypt


client = TestClient(app)

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


def test_register_user_duplicate(setup_teardown_db):
    response = client.post("/register", json={"username": "duplicateuser", "password": "testpass"})
    assert response.status_code == 200
    response = client.post("/register", json={"username": "duplicateuser", "password": "testpass"})
    assert response.status_code == 400
    assert response.json() == {"detail": "Username already registered"}


def test_marking_url_as_expired(setup_teardown_db):
    url = URL.create(original_url="http://example.com",
                     short_code="expired_code",
                     expires_at=datetime.now(tz=timezone.utc) - timedelta(days=1))
    assert url.is_expired == False
    url.mark_expired()
    assert url.is_expired == True

def test_user_password_hashing(setup_teardown_db):
    user = User.create(username='testuser', password_hash=bcrypt.hash('mypassword'))
    assert user.verify_password('mypassword') is True
    assert user.verify_password('wrongpassword') is False