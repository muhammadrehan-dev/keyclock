import os

from cryptography.fernet import Fernet

os.environ['INTERNAL_API_KEY'] = 'test-api-key-' + 'x' * 32
os.environ['TOTP_ENCRYPTION_KEY'] = Fernet.generate_key().decode()
os.environ['DATABASE_URL'] = 'sqlite://'

import pyotp
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

import app as auth


@pytest.fixture
def client(monkeypatch):
    engine = create_engine('sqlite://', connect_args={'check_same_thread': False}, poolclass=StaticPool)
    monkeypatch.setattr(auth, 'engine', engine)
    monkeypatch.setattr(auth.time, 'time', lambda: 1_800_000_000)
    with TestClient(auth.app, headers={'X-Internal-Key': auth.API_KEY}) as client:
        yield client
    engine.dispose()


credentials = {'email': 'alice@example.com', 'password': 'a very long test password'}


def headers(token):
    return {'Authorization': 'Bearer ' + token}


def signup(client):
    response = client.post('/auth/signup', json={**credentials, 'name': '  Alice Example  '})
    assert response.status_code == 201
    token = response.json()['token']
    setup = client.get('/auth/enroll', headers=headers(token)).json()
    assert setup['qr'].startswith('data:image/png;base64,')
    return token, setup['secret']


def activate(client):
    token, secret = signup(client)
    response = client.post('/auth/enroll/confirm', headers=headers(token), json={'code': pyotp.TOTP(secret).at(auth.time.time())})
    assert response.status_code == 200, response.text
    return secret, response.json()


def test_full_login_replay_and_logout(client, monkeypatch):
    secret, enrolled = activate(client)
    assert len(enrolled['recovery_codes']) == 8
    assert client.get('/auth/me', headers=headers(enrolled['token'])).json()['totp_enabled']
    assert client.get('/auth/me', headers=headers(enrolled['token'])).json()['name'] == 'Alice Example'
    challenge = client.post('/auth/login', json=credentials).json()
    assert challenge['step'] == 'mfa'
    assert client.get('/auth/me', headers=headers(challenge['token'])).status_code == 401
    assert client.post('/auth/verify', headers=headers(challenge['token']), json={'code': pyotp.TOTP(secret).at(auth.time.time())}).status_code == 401
    monkeypatch.setattr(auth.time, 'time', lambda: 1_800_000_030)
    response = client.post('/auth/verify', headers=headers(challenge['token']), json={'code': pyotp.TOTP(secret).at(auth.time.time())})
    assert response.status_code == 200
    session = response.json()['token']
    assert client.get('/auth/me', headers=headers(session)).status_code == 200
    assert client.post('/auth/verify', headers=headers(challenge['token']), json={'code': pyotp.TOTP(secret).at(auth.time.time())}).status_code == 401
    assert client.post('/auth/logout', headers=headers(session)).status_code == 200
    assert client.get('/auth/me', headers=headers(session)).status_code == 401


def test_recovery_is_one_use_and_requires_password_challenge(client):
    _, enrolled = activate(client)
    recovery = {'code': enrolled['recovery_codes'][0], 'recovery': True}
    assert client.post('/auth/verify', json=recovery).status_code == 401
    challenge = client.post('/auth/login', json=credentials).json()['token']
    assert client.post('/auth/verify', headers=headers(challenge), json=recovery).status_code == 200
    challenge = client.post('/auth/login', json=credentials).json()['token']
    assert client.post('/auth/verify', headers=headers(challenge), json=recovery).status_code == 401


def test_enrollment_scope_and_storage(client):
    token, secret = signup(client)
    assert client.get('/auth/me', headers=headers(token)).status_code == 401
    with Session(auth.engine) as db:
        user = db.scalar(select(auth.User))
        assert secret not in user.secret
        assert user.name == 'Alice Example'
        assert user.password != credentials['password']
        assert auth.cipher.decrypt(user.secret.encode()).decode() == secret
        assert db.get(auth.Ticket, auth.digest(token)) is not None
        assert db.get(auth.Ticket, token) is None


def test_expired_enrollment_and_resume(client, monkeypatch):
    token, _ = signup(client)
    monkeypatch.setattr(auth.time, 'time', lambda: 1_800_000_601)
    assert client.get('/auth/enroll', headers=headers(token)).status_code == 401
    response = client.post('/auth/login', json=credentials)
    assert response.json()['step'] == 'enroll'
    assert client.get('/auth/enroll', headers=headers(response.json()['token'])).status_code == 200


def test_otp_attempt_limit(client):
    token, secret = signup(client)
    bad = next(f'{i:06d}' for i in range(10) if all(pyotp.TOTP(secret).at(auth.time.time() + offset) != f'{i:06d}' for offset in [-30, 0, 30]))
    for _ in range(5):
        assert client.post('/auth/enroll/confirm', headers=headers(token), json={'code': bad}).status_code == 401
    response = client.post('/auth/enroll/confirm', headers=headers(token), json={'code': bad})
    assert response.status_code == 429
    assert 'retry-after' in response.headers


def test_password_limit_and_validation(client):
    signup(client)
    for _ in range(10):
        assert client.post('/auth/login', json={**credentials, 'password': 'incorrect password'}).status_code == 401
    assert client.post('/auth/login', json=credentials).status_code == 429
    assert client.post('/auth/signup', json={'email': 'not-email', 'password': 'short'}).status_code == 422


def test_enrollment_cannot_be_reopened(client):
    secret, enrolled = activate(client)
    assert client.get('/auth/enroll', headers=headers(enrolled['token'])).status_code == 401
    challenge = client.post('/auth/login', json=credentials).json()['token']
    assert client.get('/auth/enroll', headers=headers(challenge)).status_code == 401


def test_server_key_required_and_no_cache(client):
    response = client.post('/auth/login', json=credentials, headers={'X-Internal-Key': 'wrong'})
    assert response.status_code == 403
    assert response.headers['cache-control'] == 'no-store'
    assert client.get('/health', headers={'X-Internal-Key': ''}).status_code == 200


def test_leading_zero_code_and_expired_code(client, monkeypatch):
    token, secret = signup(client)
    # A known RFC secret gives deterministic leading-zero behavior.
    secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ'
    with Session(auth.engine) as db:
        user = db.scalar(select(auth.User))
        user.secret = auth.cipher.encrypt(secret.encode()).decode()
        db.commit()
    totp = pyotp.TOTP(secret)
    timestamp = next(t for t in range(1_800_000_000, 1_800_000_600, 30) if totp.at(t).startswith('0'))
    monkeypatch.setattr(auth.time, 'time', lambda: timestamp)
    assert client.post('/auth/enroll/confirm', headers=headers(token), json={'code': totp.at(timestamp - 90)}).status_code == 401
    assert client.post('/auth/enroll/confirm', headers=headers(token), json={'code': totp.at(timestamp)}).status_code == 200


@pytest.mark.parametrize('name', [None, '', '   ', 'x' * 101])
def test_registration_requires_valid_name(client, name):
    data = {**credentials}
    if name is not None:
        data['name'] = name
    assert client.post('/auth/signup', json=data).status_code == 422
    with Session(auth.engine) as db:
        assert db.scalar(select(auth.User)) is None


@pytest.mark.parametrize('email', ['alice@example.com', 'ALICE@EXAMPLE.COM'])
def test_duplicate_registration_keeps_original_account(client, email):
    signup(client)
    response = client.post('/auth/signup', json={**credentials, 'email': email, 'name': 'Someone Else'})
    assert response.status_code == 409
    assert response.json()['detail'] == 'This email is already in use. Please sign in instead.'
    with Session(auth.engine) as db:
        users = db.scalars(select(auth.User)).all()
        assert len(users) == 1
        assert users[0].name == 'Alice Example'
    assert client.post('/auth/login', json=credentials).status_code == 200


def test_existing_database_name_migration(monkeypatch):
    from sqlalchemy import text
    engine = create_engine('sqlite://')
    monkeypatch.setattr(auth, 'engine', engine)
    with engine.begin() as connection:
        connection.execute(text('CREATE TABLE users (id INTEGER PRIMARY KEY, email VARCHAR(254) UNIQUE, password VARCHAR(512), secret VARCHAR(512), enabled BOOLEAN, last_counter INTEGER)'))
        connection.execute(text("INSERT INTO users VALUES (1, 'legacy@example.com', 'old-hash', 'old-secret', 1, 42)"))
    auth.initialize_database()
    auth.initialize_database()
    with Session(engine) as db:
        user = db.get(auth.User, 1)
        assert user.name == ''
        assert (user.email, user.password, user.secret, user.enabled, user.last_counter) == ('legacy@example.com', 'old-hash', 'old-secret', True, 42)
    engine.dispose()


def message_accounts():
    tokens = {}
    with Session(auth.engine) as db:
        for name in ['Alice', 'Bob', 'Carol']:
            user = auth.User(name=name, email=name.lower() + '@example.com', password='test-only', secret='test-only', enabled=True)
            db.add(user)
            db.flush()
            tokens[name] = auth.issue(db, user, 'session', 3600)
        db.commit()
    return tokens


def test_message_delivery_and_account_isolation(client):
    tokens = message_accounts()
    response = client.post('/auth/messages', headers=headers(tokens['Alice']), json={'recipient': 'BOB@EXAMPLE.COM', 'body': '  Hello Bob!\nHow are you?  ', 'sender_id': 3})
    assert response.status_code == 201
    alice = client.get('/auth/messages', headers=headers(tokens['Alice'])).json()
    bob = client.get('/auth/messages', headers=headers(tokens['Bob'])).json()
    carol = client.get('/auth/messages', headers=headers(tokens['Carol'])).json()
    assert alice['inbox'] == [] and alice['sent_count'] == 1
    assert bob['sent'] == [] and bob['inbox_count'] == 1
    assert bob['inbox'][0]['body'] == 'Hello Bob!\nHow are you?'
    assert bob['inbox'][0]['contact'] == {'name': 'Alice', 'email': 'alice@example.com'}
    assert carol == {'inbox': [], 'sent': [], 'inbox_count': 0, 'sent_count': 0}
    assert client.post('/auth/messages', headers=headers(tokens['Bob']), json={'recipient': 'alice@example.com', 'body': 'Doing well!'}).status_code == 201
    assert client.get('/auth/messages', headers=headers(tokens['Alice'])).json()['inbox'][0]['body'] == 'Doing well!'


def test_messages_require_full_authentication(client, monkeypatch):
    token, _ = signup(client)
    for auth_headers in [{}, headers(token)]:
        assert client.get('/auth/messages', headers=auth_headers).status_code == 401
        assert client.post('/auth/messages', headers=auth_headers, json={'recipient': 'bob@example.com', 'body': 'hello'}).status_code == 401
    with Session(auth.engine) as db:
        user = db.scalar(select(auth.User))
        challenge = auth.issue(db, user, 'mfa', 300)
        session = auth.issue(db, user, 'session', 3600)
        db.commit()
    assert client.get('/auth/messages', headers=headers(challenge)).status_code == 401
    monkeypatch.setattr(auth.time, 'time', lambda: 1_800_003_601)
    assert client.get('/auth/messages', headers=headers(session)).status_code == 401


def test_message_validation_and_send_limit(client):
    tokens = message_accounts()
    sender = headers(tokens['Alice'])
    for body in ['', '  ', 'x' * 2001]:
        assert client.post('/auth/messages', headers=sender, json={'recipient': 'bob@example.com', 'body': body}).status_code == 422
    assert client.post('/auth/messages', headers=sender, json={'recipient': 'alice@example.com', 'body': 'hello'}).status_code == 400
    assert client.post('/auth/messages', headers=sender, json={'recipient': 'missing@example.com', 'body': 'hello'}).status_code == 404
    with Session(auth.engine) as db:
        db.scalar(select(auth.User).where(auth.User.email == 'carol@example.com')).enabled = False
        db.commit()
    assert client.post('/auth/messages', headers=sender, json={'recipient': 'carol@example.com', 'body': 'hello'}).status_code == 404
    for _ in range(17):
        assert client.post('/auth/messages', headers=sender, json={'recipient': 'bob@example.com', 'body': 'hello'}).status_code == 201
    assert client.post('/auth/messages', headers=sender, json={'recipient': 'bob@example.com', 'body': 'hello'}).status_code == 429


def test_mailbox_recent_limit_and_counts(client):
    tokens = message_accounts()
    with Session(auth.engine) as db:
        alice = db.scalar(select(auth.User).where(auth.User.email == 'alice@example.com'))
        bob = db.scalar(select(auth.User).where(auth.User.email == 'bob@example.com'))
        for i in range(55):
            db.add(auth.Message(sender_id=alice.id, recipient_id=bob.id, body=str(i), created_at=int(auth.time.time())))
        db.commit()
    mailbox = client.get('/auth/messages', headers=headers(tokens['Bob'])).json()
    assert mailbox['inbox_count'] == 55
    assert len(mailbox['inbox']) == 50
    assert mailbox['inbox'][0]['body'] == '54'


def test_registered_users_directory(client):
    tokens = message_accounts()
    with Session(auth.engine) as db:
        db.scalar(select(auth.User).where(auth.User.email == 'carol@example.com')).enabled = False
        db.commit()
    response = client.get('/auth/users', headers=headers(tokens['Alice']))
    assert response.status_code == 200
    data = response.json()
    assert data['total'] == 3 and data['next_cursor'] is None
    alice, bob, carol = data['users']
    assert set(alice) == {'id', 'name', 'email', 'can_message', 'is_you'}
    assert alice['is_you'] and not alice['can_message']
    assert bob['name'] == 'Bob' and bob['can_message'] and not bob['is_you']
    assert not carol['can_message']
    assert client.get('/auth/users').status_code == 401
    assert client.get('/auth/users', headers={**headers(tokens['Alice']), 'X-Internal-Key': 'wrong'}).status_code == 403
    with Session(auth.engine) as db:
        user = db.scalar(select(auth.User))
        pending = auth.issue(db, user, 'enroll', 600)
        challenge = auth.issue(db, user, 'mfa', 300)
        db.commit()
    for token in [pending, challenge]:
        assert client.get('/auth/users', headers=headers(token)).status_code == 401


def test_registered_users_pagination(client):
    tokens = message_accounts()
    with Session(auth.engine) as db:
        for i in range(52):
            db.add(auth.User(name=f'Member {i}', email=f'member{i}@example.com', password='test', secret='test'))
        db.commit()
    first = client.get('/auth/users', headers=headers(tokens['Alice'])).json()
    second = client.get('/auth/users', params={'after': first['next_cursor']}, headers=headers(tokens['Alice'])).json()
    assert first['total'] == 55 and len(first['users']) == 50
    assert len(second['users']) == 5 and second['next_cursor'] is None
    assert not ({u['id'] for u in first['users']} & {u['id'] for u in second['users']})
    assert client.get('/auth/users?after=-1', headers=headers(tokens['Alice'])).status_code == 422
