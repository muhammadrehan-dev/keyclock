# Keyclock

Python TOTP authentication with a Next.js frontend. Deploy the FastAPI backend and PostgreSQL database on Render; deploy the frontend on Vercel.

## How it works

1. Sign up with your name (1–100 characters), DUET student email (`@students.duet.edu.pk`), and password (12–128 characters). A 1-click verification link is sent via Firebase directly to your DUET inbox. Non-DUET emails are strictly rejected.
2. Verify your email by clicking the link in your DUET inbox. If you forget your password, use the "Forgot password?" feature to receive a secure reset link.
3. Scan the setup QR in Google Authenticator, Microsoft Authenticator, 1Password, or another RFC 6238 TOTP app. Manual setup is also available.
4. Enter the current six-digit code to activate the account. Save the eight recovery codes shown once.
5. Future sign-ins require your password and verified email, followed by an authenticator code or a one-use recovery code.
6. Your dashboard shows your account, message counts, Inbox and Sent folders, and a form to message another member by their registered email. Recipients must have completed authenticator setup. Use Reply to prefill the sender’s address.
7. The Registered users section lists members’ names and emails for signed-in users, including your own account marked “You.” Click Message to fill the recipient field. Accounts that have not completed authenticator setup show “Setup pending.” Refresh users updates the directory; Load more users fetches the next 50 entries.

Messages are delivered inside Keyclock, not by email. Click Refresh for new messages. Each folder displays the latest 50 messages, with a total count for the entire folder. Messages are end-to-end encrypted (E2EE) in the browser using the native Web Crypto API (`RSA-OAEP` + `AES-256-GCM` dual envelope). The server and database only store encrypted ciphertext blobs—neither server admins nor database compromises can read plaintext messages. Each user's RSA private key is encrypted client-side with a 256-bit AES-GCM key derived from their account password (`PBKDF2`, 600,000 iterations). Sending is limited to 20 attempts per user per 5-minute window. Message editing, deletion, attachments, blocking, and real-time notifications are not included in this simple dashboard.

Each account has a random secret shared with its authenticator app. The app generates six-digit SHA-1 TOTP codes locally every 30 seconds. The backend verifies codes with a ±1 time-step tolerance and rejects previously accepted time steps. Keep the server and phone clocks synchronized. There is deliberately no public endpoint exposing live OTPs.

## Run locally (PowerShell)

Prerequisites: Python 3.11+ and Node.js 20.9+.

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r backend/requirements.txt
.\.venv\Scripts\python.exe backend/setup_local.py
cd backend
..\.venv\Scripts\python.exe -m uvicorn app:app --reload
```

In another terminal from the repository root:

```powershell
cd frontend
npm install
npm run dev
```

Open http://localhost:3000. Use that exact hostname because requests are checked against `APP_ORIGIN`. Local development uses SQLite. The setup script writes ignored local secrets and refuses to overwrite existing configuration.

## Supabase database & Render backend (Free Tier)

1. **Create a free Supabase project**:
   - Go to [supabase.com](https://supabase.com) and create a free project.
   - Go to **Project Settings** > **Database** > **Connection string** (or click the **Connect** button at the top).
   - Under **URI**, select **Connection Pooling** (Mode: **Session** or **Transaction**, port `5432` or `6543`) to get an IPv4-compatible URL (e.g. `postgresql://postgres.[REF]:[PASSWORD]@aws-0-[REGION].pooler.supabase.com:6543/postgres`).
     *(Note: Render free services only support IPv4 outgoing traffic, so always use the Pooler URL rather than direct IPv6).*

2. **Deploy Backend to Render**:
   - Push this project to your Git provider and create a Render Blueprint from `render.yaml` (or create a Web Service directly on the Free plan).
   - In Render, provide the following environment variables:
     - `DATABASE_URL`: Your Supabase pooler connection URI (replace `[YOUR-PASSWORD]` with your real database password).
     - `TOTP_ENCRYPTION_KEY`: Generate a key locally:
       ```powershell
       .\.venv\Scripts\python.exe -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
       ```
     - `INTERNAL_API_KEY`: Render generates this automatically (or generate a random 32+ character string). Copy this key for Vercel.
     - `TOTP_ISSUER`: Set to your app name (default: `Keyclock`).
3. Verify `https://YOUR-API.onrender.com/health` returns `{"status":"ok"}`. The API will automatically create the required database tables on Supabase upon first startup.

## Vercel frontend

Import the same repository, select the **Next.js** preset, and set the **Root Directory** to `frontend`. Set these server-only environment variables:

| Variable | Value |
| --- | --- |
| `BACKEND_URL` | Your Render API HTTPS origin, no trailing slash |
| `INTERNAL_API_KEY` | Exactly the Render API key |
| `APP_ORIGIN` | Your frontend HTTPS origin, no trailing slash |

Deploy, then update `APP_ORIGIN` to the assigned production domain if necessary and redeploy. Preview deployments need their own matching origin and ideally a separate test backend/database. Do not prefix these variables with `NEXT_PUBLIC_`.

The browser calls same-origin Next.js route handlers. Vercel forwards requests to Render and keeps the opaque token in a Secure, HTTP-only, SameSite=Lax cookie in production. No cross-site cookies or browser-to-Render CORS configuration is needed. Mutating requests require the exact configured Origin and JSON content type. The API rejects requests without its server-to-server key, except `/health` and API documentation.

## Checks

```powershell
cd backend
..\.venv\Scripts\python.exe -m pytest -q
cd ../frontend
npm run build
```

Tests use isolated in-memory SQLite databases. PostgreSQL deployment and concurrency checks should also be run against a staging database before public rollout.

With both local servers running, run `..\.venv\Scripts\python.exe smoke_proxy.py` from `backend` to check the Next.js proxy, cookies, origin validation, and full enrollment/recovery login flow. It removes its own temporary account afterward.

## Security and current scope

- Primary identity is verified via Firebase ID tokens (verified against Google's public keys for project audience, email verification, and the @students.duet.edu.pk domain). Backend passwords are not stored. Authenticator secrets are Fernet-encrypted. Session tokens and recovery codes are stored as SHA-256 digests of high-entropy values.
- Enrollment tickets last 10 minutes, password-verified login challenges last 5 minutes, and authenticated sessions last 1 hour. Logout revokes the current ticket. Expired tickets are cleaned during rate-limit checks.
- Database-backed atomic fixed-window limits enforce 5 OTP attempts per account and 15 attempts per IP per 5 minutes; 10 login attempts per email and 30 per IP; and per-user message sending limits. Global limits are maintained alongside IP/account limits to mitigate lockout abuse.
- OTP acceptance, recovery-code consumption, and challenge consumption are transactional; accepted time steps cannot be replayed. After enrollment, wait for the next authenticator code before testing a new login.
- Back up the database **and** encryption key separately. Replacing the key without migrating encrypted secrets prevents existing users from authenticating. Never log QR codes, passwords, secrets, cookies, or recovery codes.
- Email ownership verification and password reset are handled via Firebase Auth. Authenticator replacement/disable, recovery-code regeneration, and session management across multiple devices are not implemented in this starter. Recovery codes restore a sign-in, but do not enroll a replacement phone. If all factors are lost, there is no self-service recovery flow.
- TOTP is not phishing-resistant. This starter is ready for local development and deployment configuration, not a claim of a production security audit.

References: [PyOTP](https://pyotp.readthedocs.io/en/stable/), [Render FastAPI deployment](https://render.com/docs/deploy-fastapi), [Next.js cookies](https://nextjs.org/docs/app/api-reference/functions/cookies).
