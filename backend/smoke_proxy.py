"""Optional integration check against local running API + Next.js dev servers."""
import uuid

import httpx
import pyotp
from sqlalchemy import delete, or_, select
from sqlalchemy.orm import Session

from app import Message, Recovery, Ticket, User, engine


def main():
    email = f'smoke-{uuid.uuid4().hex}@example.com'
    recipient_email = 'recipient-' + email
    credentials = {'email': email, 'password': 'Disposable local smoke test password'}
    try:
        with httpx.Client(base_url='http://localhost:3000/api/auth/', headers={'Origin': 'http://localhost:3000'}, timeout=60) as client:
            registration = {**credentials, 'name': 'Smoke Test'}
            response = client.post('signup', json=registration, headers={'Origin': 'https://untrusted.example'})
            assert response.status_code == 403, response.text
            response = client.post('signup', json=registration)
            assert response.status_code == 201, response.text
            assert 'token' not in response.json()
            assert 'HttpOnly' in response.headers['set-cookie']
            assert 'SameSite=lax' in response.headers['set-cookie']
            duplicate = client.post('signup', json={**registration, 'email': email.upper()})
            assert duplicate.status_code == 409, duplicate.text
            assert duplicate.json()['detail'] == 'This email is already in use. Please sign in instead.'
            assert client.get('me').status_code == 401
            # The failed /me request clears the pending cookie: resume enrollment.
            assert client.post('login', json=credentials).json()['step'] == 'enroll'
            setup = client.get('enroll').json()
            response = client.post('enroll/confirm', json={'code': pyotp.TOTP(setup['secret']).now()})
            assert response.status_code == 200, response.text
            assert 'token' not in response.json()
            recovery = response.json()['recovery_codes'][0]
            assert client.get('me').json()['email'] == email
            assert client.get('me').json()['name'] == 'Smoke Test'
            assert client.post('logout', json={}).status_code == 200
            assert client.get('me').status_code == 401
            assert client.post('login', json=credentials).json()['step'] == 'mfa'
            assert client.post('verify', json={'code': recovery, 'recovery': True}).status_code == 200
            assert client.get('me').json()['totp_enabled']
            with httpx.Client(base_url='http://localhost:3000/api/auth/', headers={'Origin': 'http://localhost:3000'}, timeout=60) as recipient:
                result = recipient.post('signup', json={'email': recipient_email, 'password': credentials['password'], 'name': 'Test Recipient'})
                assert result.status_code == 201, result.text
                setup = recipient.get('enroll').json()
                result = recipient.post('enroll/confirm', json={'code': pyotp.TOTP(setup['secret']).now()})
                assert result.status_code == 200, result.text
                assert client.get('messages').json()['inbox'] == []
                directory = client.get('users').json()
                own_entry = next(member for member in directory['users'] if member['email'] == email)
                assert own_entry['is_you'] and not own_entry['can_message']
                assert any(member['email'] == recipient_email and member['can_message'] for member in directory['users'])
                assert all(member['id'] > own_entry['id'] for member in client.get('users', params={'after': own_entry['id']}).json()['users'])
                result = client.post('messages', json={'recipient': recipient_email.upper(), 'body': 'Hello from the integration test!'})
                assert result.status_code == 201, result.text
                inbox = recipient.get('messages').json()
                assert inbox['inbox'][0]['body'] == 'Hello from the integration test!'
                assert inbox['inbox'][0]['contact']['email'] == email
                assert client.get('messages').json()['sent_count'] == 1
                assert recipient.post('logout', json={}).status_code == 200
            assert client.post('logout', json={}).status_code == 200
            print('PASS: origin validation, cookies, enrollment, recovery login, message delivery, mailbox isolation, logout.')
    finally:
        with Session(engine) as db:
            for user in db.scalars(select(User).where(User.email.in_([email, recipient_email]))).all():
                db.execute(delete(Message).where(or_(Message.sender_id == user.id, Message.recipient_id == user.id)))
                db.execute(delete(Ticket).where(Ticket.user_id == user.id))
                db.execute(delete(Recovery).where(Recovery.user_id == user.id))
                db.delete(user)
                db.commit()


if __name__ == '__main__':
    main()
