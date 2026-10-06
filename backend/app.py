"""Password + authenticator login. Run with uvicorn app:app."""
import base64
import hashlib
import io
import os
import re
import secrets
import time
from contextlib import asynccontextmanager

import pyotp
import qrcode
from cryptography.fernet import Fernet
from dotenv import load_dotenv
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from pydantic import BaseModel, EmailStr, Field, field_validator
from pwdlib import PasswordHash
from sqlalchemy import Boolean, ForeignKey, Integer, String, create_engine, delete, func, inspect, select, text, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

load_dotenv()
API_KEY = os.environ['INTERNAL_API_KEY']
if len(API_KEY) < 32:
    raise RuntimeError('INTERNAL_API_KEY must be at least 32 characters')
cipher = Fernet(os.environ['TOTP_ENCRYPTION_KEY'].encode())
url = os.getenv('DATABASE_URL', 'sqlite:///./totp.db')
if url.startswith(('postgres://', 'postgresql://')):
    url = 'postgresql+psycopg://' + url.split('://', 1)[1]
engine = create_engine(url, pool_pre_ping=True, connect_args={'check_same_thread': False} if url.startswith('sqlite') else {})
passwords = PasswordHash.recommended()
dummy_hash = passwords.hash(secrets.token_urlsafe(32))


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = 'users'
    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(254), unique=True)
    name: Mapped[str] = mapped_column(String(100), server_default='')
    password: Mapped[str] = mapped_column(String(512))
    secret: Mapped[str] = mapped_column(String(512))
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    last_counter: Mapped[int] = mapped_column(Integer, default=-1)


class Ticket(Base):
    __tablename__ = 'tickets'
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    scope: Mapped[str] = mapped_column(String(16))
    expires: Mapped[int] = mapped_column(Integer, index=True)


class Recovery(Base):
    __tablename__ = 'recovery_codes'
    digest: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)


class Throttle(Base):
    __tablename__ = 'throttles'
    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    count: Mapped[int] = mapped_column(Integer)
    expires: Mapped[int] = mapped_column(Integer, index=True)


class Message(Base):
    __tablename__ = 'messages'
    id: Mapped[int] = mapped_column(primary_key=True)
    sender_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    recipient_id: Mapped[int] = mapped_column(ForeignKey('users.id'), index=True)
    body: Mapped[str] = mapped_column(String(2000))
    created_at: Mapped[int] = mapped_column(Integer)


def initialize_database():
    Base.metadata.create_all(engine)
    # Additive migration for accounts created before registration collected names.
    with engine.begin() as connection:
        if 'name' not in {column['name'] for column in inspect(connection).get_columns('users')}:
            optional = 'IF NOT EXISTS ' if connection.dialect.name == 'postgresql' else ''
            connection.execute(text(f"ALTER TABLE users ADD COLUMN {optional}name VARCHAR(100) NOT NULL DEFAULT ''"))


@asynccontextmanager
async def lifespan(app):
    initialize_database()
    yield


app = FastAPI(title='Keyclock authentication', lifespan=lifespan)


@app.middleware('http')
async def no_store(request: Request, call_next):
    response = await call_next(request)
    response.headers['Cache-Control'] = 'no-store'
    return response


def db_session():
    with Session(engine) as db:
        yield db


def internal(x_internal_key: str = Header(default='')):
    if not secrets.compare_digest(x_internal_key, API_KEY):
        raise HTTPException(403, 'Forbidden')


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def limit(key, maximum=10, seconds=300):
    """Shared, atomic fixed-window limits (also count unsuccessful attempts)."""
    now = int(time.time())
    bucket = digest(f'{key}:{now // seconds}')
    with Session(engine) as db:
        db.execute(delete(Throttle).where(Throttle.expires < now))
        db.execute(delete(Ticket).where(Ticket.expires < now))
        db.commit()
        try:
            db.add(Throttle(key=bucket, count=0, expires=(now // seconds + 1) * seconds))
            db.commit()
        except IntegrityError:
            db.rollback()
        accepted = db.execute(update(Throttle).where(Throttle.key == bucket, Throttle.count < maximum).values(count=Throttle.count + 1)).rowcount
        db.commit()
    if not accepted:
        raise HTTPException(429, 'Too many attempts. Please wait a few minutes.', headers={'Retry-After': str(seconds - now % seconds)})


def issue(db, user, scope, lifetime):
    token = secrets.token_urlsafe(32)
    db.add(Ticket(digest=digest(token), user_id=user.id, scope=scope, expires=int(time.time()) + lifetime))
    return token


def ticket(db, authorization, scope):
    token = authorization.removeprefix('Bearer ')
    found = db.get(Ticket, digest(token))
    if not found or found.scope != scope or found.expires <= time.time():
        raise HTTPException(401, 'Session expired. Please sign in again.')
    return found


def consume(db, found):
    if db.execute(delete(Ticket).where(Ticket.digest == found.digest)).rowcount != 1:
        raise HTTPException(401, 'This sign-in request has already been used.')


def check_code(db, user, code):
    if not re.fullmatch(r'[0-9]{6}', code):
        raise HTTPException(400, 'Enter a six-digit authenticator code.')
    totp = pyotp.TOTP(cipher.decrypt(user.secret.encode()).decode())
    current = int(time.time()) // 30
    for counter in (current, current - 1, current + 1):
        if secrets.compare_digest(totp.at(counter * 30), code):
            changed = db.execute(update(User).where(User.id == user.id, User.last_counter < counter).values(last_counter=counter)).rowcount
            if changed:
                return
            break
    raise HTTPException(401, 'Invalid or already-used code. Try the next code in your app.')


class Credentials(BaseModel):
    email: EmailStr = Field(max_length=254)
    password: str = Field(min_length=12, max_length=128)


class Registration(Credentials):
    name: str = Field(min_length=1, max_length=100)

    @field_validator('name', mode='before')
    @classmethod
    def trim_name(cls, value):
        return value.strip() if isinstance(value, str) else value


class Code(BaseModel):
    code: str = Field(min_length=6, max_length=40)
    recovery: bool = False


class NewMessage(BaseModel):
    recipient: EmailStr = Field(max_length=254)
    body: str = Field(min_length=1, max_length=2000)

    @field_validator('body', mode='before')
    @classmethod
    def trim_body(cls, value):
        return value.strip() if isinstance(value, str) else value


private = [Depends(internal)]


@app.get('/health')
def health():
    with engine.connect() as connection:
        connection.execute(select(1))
    return {'status': 'ok'}


@app.post('/auth/signup', dependencies=private, status_code=201)
def signup(data: Registration, db: Session = Depends(db_session)):
    email = str(data.email).lower()
    limit('signup-global', 50, 3600)
    limit('signup:' + email, 3, 3600)
    if db.scalar(select(User.id).where(User.email == email)) is not None:
        raise HTTPException(409, 'This email is already in use. Please sign in instead.')
    user = User(name=data.name, email=email, password=passwords.hash(data.password), secret=cipher.encrypt(pyotp.random_base32().encode()).decode())
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        # The unique constraint also handles simultaneous registrations.
        if db.scalar(select(User.id).where(User.email == email)) is not None:
            raise HTTPException(409, 'This email is already in use. Please sign in instead.')
        raise
    token = issue(db, user, 'enroll', 600)
    db.commit()
    return {'token': token, 'step': 'enroll'}


@app.post('/auth/login', dependencies=private)
def login(data: Credentials, db: Session = Depends(db_session)):
    email = str(data.email).lower()
    limit('login-global', 300, 300)
    limit('login:' + email)
    user = db.scalar(select(User).where(User.email == email))
    valid = passwords.verify(data.password, user.password if user else dummy_hash)
    if not user or not valid:
        raise HTTPException(401, 'Incorrect email or password.')
    scope = 'mfa' if user.enabled else 'enroll'
    token = issue(db, user, scope, 300 if user.enabled else 600)
    db.commit()
    return {'token': token, 'step': scope}


@app.get('/auth/enroll', dependencies=private)
def enroll(authorization: str = Header(default=''), db: Session = Depends(db_session)):
    found = ticket(db, authorization, 'enroll')
    user = db.get(User, found.user_id)
    if user.enabled:
        raise HTTPException(409, 'Authenticator already enabled.')
    secret = cipher.decrypt(user.secret.encode()).decode()
    uri = pyotp.TOTP(secret).provisioning_uri(name=user.email, issuer_name=os.getenv('TOTP_ISSUER', 'Keyclock'))
    buffer = io.BytesIO()
    qrcode.make(uri).save(buffer, kind='PNG')
    return {'secret': secret, 'qr': 'data:image/png;base64,' + base64.b64encode(buffer.getvalue()).decode()}


@app.post('/auth/enroll/confirm', dependencies=private)
def confirm(data: Code, authorization: str = Header(default=''), db: Session = Depends(db_session)):
    found = ticket(db, authorization, 'enroll')
    limit('otp:' + str(found.user_id), 5)
    user = db.get(User, found.user_id)
    if user.enabled:
        raise HTTPException(409, 'Authenticator already enabled.')
    check_code(db, user, data.code)
    # Atomic activation prevents two concurrent enrollment confirmations.
    if db.execute(update(User).where(User.id == user.id, User.enabled == False).values(enabled=True)).rowcount != 1:
        raise HTTPException(409, 'Authenticator already enabled.')
    codes = [secrets.token_hex(8) for _ in range(8)]
    for code in codes:
        db.add(Recovery(user_id=user.id, digest=digest(code)))
    db.execute(delete(Ticket).where(Ticket.user_id == user.id))
    token = issue(db, user, 'session', 3600)
    db.commit()
    return {'token': token, 'step': 'session', 'recovery_codes': codes, 'name': user.name, 'email': user.email}


@app.post('/auth/verify', dependencies=private)
def verify(data: Code, authorization: str = Header(default=''), db: Session = Depends(db_session)):
    found = ticket(db, authorization, 'mfa')
    limit('otp:' + str(found.user_id), 5)
    user = db.get(User, found.user_id)
    if data.recovery:
        changed = db.execute(delete(Recovery).where(Recovery.user_id == user.id, Recovery.digest == digest(data.code.strip().lower()))).rowcount
        if not changed:
            raise HTTPException(401, 'Invalid or already-used recovery code.')
    else:
        check_code(db, user, data.code)
    consume(db, found)
    token = issue(db, user, 'session', 3600)
    db.commit()
    return {'token': token, 'step': 'session'}


@app.get('/auth/me', dependencies=private)
def me(authorization: str = Header(default=''), db: Session = Depends(db_session)):
    found = ticket(db, authorization, 'session')
    user = db.get(User, found.user_id)
    return {'name': user.name, 'email': user.email, 'totp_enabled': user.enabled}


@app.post('/auth/logout', dependencies=private)
def logout(authorization: str = Header(default=''), db: Session = Depends(db_session)):
    db.execute(delete(Ticket).where(Ticket.digest == digest(authorization.removeprefix('Bearer '))))
    db.commit()
    return {'ok': True}


@app.get('/auth/messages', dependencies=private)
def messages(authorization: str = Header(default=''), db: Session = Depends(db_session)):
    found = ticket(db, authorization, 'session')
    result = {}
    for folder, owner, contact in [('inbox', Message.recipient_id, Message.sender_id), ('sent', Message.sender_id, Message.recipient_id)]:
        rows = db.execute(select(Message, User).join(User, User.id == contact).where(owner == found.user_id).order_by(Message.id.desc()).limit(50)).all()
        result[folder] = [{'id': message.id, 'body': message.body, 'created_at': message.created_at,
                           'contact': {'name': user.name, 'email': user.email}} for message, user in rows]
        result[folder + '_count'] = db.scalar(select(func.count()).select_from(Message).where(owner == found.user_id))
    return result


@app.get('/auth/users', dependencies=private)
def registered_users(after: int = Query(default=0, ge=0), authorization: str = Header(default=''), db: Session = Depends(db_session)):
    found = ticket(db, authorization, 'session')
    rows = db.execute(select(User.id, User.name, User.email, User.enabled).where(User.id > after).order_by(User.id).limit(51)).all()
    return {
        'users': [{'id': user.id, 'name': user.name, 'email': user.email, 'can_message': user.enabled and user.id != found.user_id,
                   'is_you': user.id == found.user_id} for user in rows[:50]],
        'total': db.scalar(select(func.count()).select_from(User)),
        'next_cursor': rows[49].id if len(rows) > 50 else None,
    }


@app.post('/auth/messages', dependencies=private, status_code=201)
def send_message(data: NewMessage, authorization: str = Header(default=''), db: Session = Depends(db_session)):
    found = ticket(db, authorization, 'session')
    limit('messages:' + str(found.user_id), 20, 300)
    recipient = db.scalar(select(User).where(User.email == str(data.recipient).lower(), User.enabled == True))
    if not recipient:
        raise HTTPException(404, 'No active account found for that email. Check the address and try again.')
    if recipient.id == found.user_id:
        raise HTTPException(400, 'Enter another user’s email address.')
    message = Message(sender_id=found.user_id, recipient_id=recipient.id, body=data.body, created_at=int(time.time()))
    db.add(message)
    db.commit()
    return {'id': message.id, 'detail': 'Message sent.'}
