"""Generate local-only configuration without overwriting existing credentials."""
from pathlib import Path
import secrets

from cryptography.fernet import Fernet

root = Path(__file__).resolve().parent.parent
backend = root / 'backend' / '.env'
frontend = root / 'frontend' / '.env.local'
if backend.exists() or frontend.exists():
    raise SystemExit('Configuration already exists. Update the existing files manually; no files changed.')
api_key = secrets.token_urlsafe(32)
backend.write_text(f'DATABASE_URL=sqlite:///./totp.db\nINTERNAL_API_KEY={api_key}\nTOTP_ENCRYPTION_KEY={Fernet.generate_key().decode()}\nTOTP_ISSUER=Keyclock\n')
frontend.write_text(f'BACKEND_URL=http://127.0.0.1:8000\nINTERNAL_API_KEY={api_key}\nAPP_ORIGIN=http://localhost:3000\n')
print('Created backend/.env and frontend/.env.local. Keep both private.')
