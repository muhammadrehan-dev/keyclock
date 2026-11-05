'use client';

import { FormEvent, useEffect, useRef, useState } from 'react';
import Dashboard from './dashboard';
import { CheckIcon, ShieldIcon } from './icons';
import {
  clearPrivateKeyFromSession,
  decryptPrivateKeyWithPassword,
  encryptPrivateKeyWithPassword,
  exportPublicKey,
  generateE2EEKeyPair,
  savePrivateKeyToSession,
} from './crypto';
import {
  createUserWithEmailAndPassword,
  sendEmailVerification,
  sendPasswordResetEmail,
  signInWithEmailAndPassword,
  updateProfile,
} from 'firebase/auth';
import { auth } from './firebase';

type Step = 'login' | 'signup' | 'verify-notice' | 'forgot-password' | 'enroll' | 'mfa' | 'recovery' | 'saved' | 'session';
type Enrollment = { secret: string; qr: string };

const DUET_DOMAIN = '@students.duet.edu.pk';

function isDuetEmail(value: string): boolean {
  return value.trim().toLowerCase().endsWith(DUET_DOMAIN);
}

async function api(path: string, body?: object) {
  const response = await fetch(`/api/auth/${path}`, {
    method: body ? 'POST' : 'GET',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined, cache: 'no-store',
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || 'Something went wrong. Please try again.');
  return data;
}

export default function Home() {
  const [step, setStep] = useState<Step>('login');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);
  const [keyResetPrompt, setKeyResetPrompt] = useState<{ password: string; totpCode: string } | null>(null);
  const pwdRef = useRef('');

  useEffect(() => {
    api('me').then(data => { setEmail(data.email); setName(data.name); setStep('session'); })
      .catch(() => {}).finally(() => setLoading(false));
  }, []);

  function change(next: Step) {
    setStep(next);
    setError('');
    setNotice('');
    setCode('');
    setShowPassword(false);
  }

  async function initE2EEKeys(enteredPassword: string, totpCode?: string): Promise<boolean> {
    try {
      const keysData = await api('keys');
      if (keysData.encrypted_private_key && keysData.public_key) {
        try {
          const { privateKey, needsRewrap, jwk } = await decryptPrivateKeyWithPassword(keysData.encrypted_private_key, enteredPassword);
          await savePrivateKeyToSession(jwk);
          if (needsRewrap) {
            try {
              const rewrapped = await encryptPrivateKeyWithPassword(jwk, enteredPassword, 600000);
              await api('keys', {
                public_key: keysData.public_key,
                encrypted_private_key: rewrapped,
              });
            } catch (rewrapErr) {
              console.warn('Note: re-wrapping key bundle postponed:', rewrapErr);
            }
          }
          return true;
        } catch (decryptErr) {
          console.warn('Could not decrypt stored private key with current password:', decryptErr);
          setKeyResetPrompt({
            password: enteredPassword,
            totpCode: totpCode || '',
          });
          return false;
        }
      } else {
        const keyPair = await generateE2EEKeyPair();
        const pubJwk = await exportPublicKey(keyPair.publicKey);
        const encPriv = await encryptPrivateKeyWithPassword(keyPair.privateKey, enteredPassword, 600000);
        await api('keys', { public_key: pubJwk, encrypted_private_key: encPriv });
        const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        await savePrivateKeyToSession(privJwk);
        return true;
      }
    } catch (err) {
      console.error('E2EE key initialization error:', err);
      return true;
    }
  }

  async function handleResetKeypair() {
    if (!keyResetPrompt) return;
    setBusy(true); setError('');
    try {
      const keyPair = await generateE2EEKeyPair();
      const pubJwk = await exportPublicKey(keyPair.publicKey);
      const encPriv = await encryptPrivateKeyWithPassword(keyPair.privateKey, keyResetPrompt.password, 600000);
      await api('keys', {
        public_key: pubJwk,
        encrypted_private_key: encPriv,
        code: keyResetPrompt.totpCode,
      });
      const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
      await savePrivateKeyToSession(privJwk);
      setKeyResetPrompt(null);
      setNotice('New encryption keypair generated successfully.');
      change('session');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not generate new keypair.');
    } finally {
      setBusy(false);
    }
  }

  async function resendVerification() {
    setBusy(true); setError(''); setNotice('');
    try {
      if (auth.currentUser) {
        await sendEmailVerification(auth.currentUser);
        setNotice('A new verification email has been sent to your DUET inbox!');
      } else {
        setError('Please sign in first to request a new verification link.');
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Could not resend verification email.');
    } finally {
      setBusy(false);
    }
  }

  async function handleVerifiedNotice() {
    setBusy(true); setError(''); setNotice('');
    try {
      if (auth.currentUser) {
        await auth.currentUser.reload();
        if (auth.currentUser.emailVerified) {
          const idToken = await auth.currentUser.getIdToken();
          try {
            const data = await api('signup', { id_token: idToken, name: auth.currentUser.displayName || name.trim() || 'DUET Student' });
            change(data.step);
            if (data.step === 'enroll') setEnrollment(await api('enroll'));
            return;
          } catch (signupErr: unknown) {
            if (signupErr instanceof Error && signupErr.message.includes('already in use')) {
              change('login');
              return;
            }
            throw signupErr;
          }
        }
      }
      change('login');
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Please sign in to continue.');
      change('login');
    } finally {
      setBusy(false);
    }
  }

  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError(''); setNotice('');
    try {
      const cleanEmail = email.trim().toLowerCase();

      if (step === 'signup') {
        if (!name.trim()) throw new Error('Please enter your name.');
        if (!isDuetEmail(cleanEmail)) {
          throw new Error(`Only DUET students with a ${DUET_DOMAIN} email address can register.`);
        }

        // 1. Create account in Firebase and send 1-click verification link
        try {
          const userCred = await createUserWithEmailAndPassword(auth, cleanEmail, password);
          await updateProfile(userCred.user, { displayName: name.trim() });
          await sendEmailVerification(userCred.user);
        } catch (fbErr: unknown) {
          const code = (fbErr as { code?: string })?.code;
          if (code === 'auth/email-already-in-use') {
            throw new Error('This email is already registered. Please switch to the "Sign in" tab to continue.');
          }
          throw new Error((fbErr as Error).message || 'Firebase registration failed.');
        }

        change('verify-notice');
      } else if (step === 'login') {
        if (!isDuetEmail(cleanEmail)) {
          throw new Error(`Please sign in with your ${DUET_DOMAIN} student email address.`);
        }

        // 1. Verify in Firebase and check if email is verified
        let idToken = '';
        try {
          const userCred = await signInWithEmailAndPassword(auth, cleanEmail, password);
          await userCred.user.reload();
          if (!userCred.user.emailVerified) {
            throw new Error('Your email is not verified yet! Please click the 1-click verification link sent to your DUET inbox. You can also resend it below.');
          }
          idToken = await userCred.user.getIdToken();
        } catch (fbErr: unknown) {
          const code = (fbErr as { code?: string })?.code;
          if (code === 'auth/invalid-credential' || code === 'auth/wrong-password' || code === 'auth/user-not-found') {
            throw new Error('Incorrect email or password.');
          }
          throw fbErr;
        }

        // 2. Sign in to Keyclock backend session using verified Firebase ID token
        pwdRef.current = password;
        const data = await api('login', { id_token: idToken });

        setPassword('');
        change(data.step);
        if (data.step === 'enroll') setEnrollment(await api('enroll'));
      } else if (step === 'forgot-password') {
        if (!isDuetEmail(cleanEmail)) {
          throw new Error(`Please enter your valid ${DUET_DOMAIN} student email.`);
        }
        await sendPasswordResetEmail(auth, cleanEmail);
        setNotice('Password reset link sent! Check your DUET inbox to set a new password.');
      } else {
        // MFA verification or enrollment confirmation
        const lastCode = code;
        const data = await api(step === 'enroll' ? 'enroll/confirm' : 'verify', { code, recovery: step === 'recovery' });
        setCode(''); setEnrollment(null);
        let keyInitOk = true;
        if (pwdRef.current) {
          keyInitOk = await initE2EEKeys(pwdRef.current, lastCode);
          pwdRef.current = '';
        }
        if (data.recovery_codes) {
          setName(data.name); setEmail(data.email); setCodes(data.recovery_codes); setSaved(false); change('saved');
        } else if (!keyInitOk) {
          const profile = await api('me');
          setEmail(profile.email); setName(profile.name);
        } else {
          const profile = await api('me');
          setEmail(profile.email); setName(profile.name); change('session');
        }
      }
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : 'Please try again.');
    } finally {
      setBusy(false);
    }
  }

  async function logout() {
    setBusy(true); setError('');
    try {
      await api('logout', {});
      clearPrivateKeyFromSession();
      setEnrollment(null); setCodes([]); setPassword(''); setName(''); change('login');
    }
    catch (e: unknown) { setError(e instanceof Error ? e.message : 'Sign out failed.'); }
    finally { setBusy(false); }
  }

  const credentials = step === 'login' || step === 'signup';
  const titles: Record<Step, string> = {
    login: 'Welcome back.',
    signup: 'DUET Student Access.',
    'verify-notice': 'Check your DUET inbox.',
    'forgot-password': 'Reset your password.',
    enroll: 'Meet your second layer.',
    mfa: 'One more little step.',
    recovery: 'Use a recovery code.',
    saved: 'Keep a spare key.',
    session: 'You’re securely signed in.',
  };
  const descriptions: Record<Step, string> = {
    login: 'Sign in with your DUET student account. Authenticator & Firebase protected.',
    signup: 'Only @students.duet.edu.pk email addresses are allowed to register.',
    'verify-notice': `We sent a 1-click verification link to ${email || 'your DUET email'}. Open your inbox and click the link to verify.`,
    'forgot-password': 'Enter your student email address. We will send you a secure link to reset your password.',
    enroll: 'Scan this QR code with Google Authenticator, Microsoft Authenticator, or another TOTP app.',
    mfa: 'Enter the six-digit code from your authenticator app. Codes refresh every 30 seconds.',
    recovery: 'Each recovery code works once. Your account password has already been verified.',
    saved: 'Save these eight one-use recovery codes somewhere private. They let you sign in if you lose your phone.',
    session: 'Your student credentials and authenticator have both been verified.',
  };

  if (step === 'session') return <Dashboard name={name} email={email} onLogout={logout} busy={busy} error={error} />;

  return <main>
    <header>
      <a className="brand" href="/" aria-label="DUETCLOCK home"><span className="brandmark">D</span>DUETCLOCK<span className="branddot">®</span></a>
      <span className="header-note"><span className="dot" /> DUET Student Portal • E2EE</span>
    </header>
    <div className="shell">
      <aside>
        <div className="eyebrow">DUET STUDENT MESSAGING</div>
        <h1>A second layer.<br /><em>A safer space.</em></h1>
        <p className="intro">End-to-end encrypted messaging exclusively for Dawood University of Engineering & Technology students.</p>
        <div className="illustration" aria-hidden="true"><div className="orbit one" /><div className="orbit two" /><div className="clock"><span className="clock-pin" /><span className="clock-hand" /><span className="clock-hand short" /></div><span className="mini-badge"><CheckIcon size={12} /></span><div className="floating-label">@students.duet.edu.pk ONLY</div></div>
        <div className="aside-footer"><span className="small-star"><ShieldIcon size={14} style={{ color: 'var(--green)' }} /></span><p>Verified with Firebase Email Link.<br /><strong>Protected by Authenticator TOTP & Web Crypto E2EE.</strong></p></div>
      </aside>
      <section className="card" aria-labelledby="form-title" aria-busy={busy || loading}>
        <div className="card-top">
          <span className="eyebrow">DUET ACCESS</span>
          <span className="step-chip">{credentials ? '01 / 02' : '02 / 02'}</span>
        </div>
        {loading ? <p role="status">Checking your session…</p> : <>
          {credentials && (
            <div className="tabs">
              <button type="button" disabled={busy} className={step === 'login' ? 'active' : ''} onClick={() => change('login')}>Sign in</button>
              <button type="button" disabled={busy} className={step === 'signup' ? 'active' : ''} onClick={() => change('signup')}>Create account</button>
            </div>
          )}
          <h2 id="form-title">{keyResetPrompt ? 'Encryption Key Inaccessible' : titles[step]}</h2>
          <p className="description">{keyResetPrompt ? 'Your account password was recently changed or reset.' : descriptions[step]}</p>
          {error && <div className="error" role="alert">{error}</div>}
          {notice && <div className="send-success" style={{ margin: '15px 0' }} role="status"><CheckIcon size={14} style={{ marginRight: 4 }} /> {notice}</div>}

          {keyResetPrompt ? (
            <div style={{ background: '#fff0e9', border: '1px solid #ffd4c2', borderRadius: 10, padding: 16, margin: '16px 0' }} role="alert">
              <strong style={{ color: '#be2e15', display: 'block', marginBottom: 6 }}>Password Reset Detected</strong>
              <p style={{ fontSize: 13, color: 'var(--ink)', lineHeight: 1.5, margin: '0 0 12px' }}>
                Your account password was recently changed, so your existing private key cannot be unlocked with the new password.
                <br /><br />
                <strong>Warning:</strong> Generating a new keypair lets you send and receive new messages, but previously received encrypted messages can no longer be decrypted.
              </p>
              <div style={{ display: 'flex', gap: 10 }}>
                <button type="button" className="primary" style={{ padding: '8px 16px', fontSize: 13 }} disabled={busy} onClick={handleResetKeypair}>
                  {busy ? 'Generating Keypair…' : 'Generate New Keypair ↗'}
                </button>
                <button type="button" className="text-button" style={{ margin: 0, fontSize: 13 }} disabled={busy} onClick={() => { setKeyResetPrompt(null); change('session'); }}>
                  Skip for now
                </button>
              </div>
            </div>
          ) : <>

          {step === 'verify-notice' && (
            <div>
              <p className="intro" style={{ marginBottom: '20px' }}>
                Please check your inbox at <strong>{email}</strong> (check Spam or Junk folder if not in primary inbox). Click the verification link inside, then return here to sign in.
              </p>
              <button className="primary" type="button" onClick={handleVerifiedNotice}>
                I have verified my email → Sign in <span>↗</span>
              </button>
              <button className="text-button" type="button" disabled={busy} onClick={resendVerification}>
                Didn’t get the email? Resend verification link
              </button>
            </div>
          )}

          {step === 'forgot-password' && (
            <form onSubmit={submit}>
              <fieldset disabled={busy}>
                <label htmlFor="email">DUET Student Email</label>
                <input
                  id="email"
                  type="email"
                  autoComplete="username"
                  placeholder="e.g. k21-ce-42@students.duet.edu.pk"
                  maxLength={254}
                  required
                  value={email}
                  onChange={e => setEmail(e.target.value)}
                />
                <button className="primary" type="submit" disabled={busy || !email.trim()}>
                  {busy ? 'Sending link…' : 'Send password reset link'} <span aria-hidden="true">↗</span>
                </button>
                <button className="text-button" type="button" onClick={() => change('login')}>
                  Back to sign in
                </button>
              </fieldset>
            </form>
          )}

          {(credentials || ['enroll', 'mfa', 'recovery'].includes(step)) && (
            <form onSubmit={submit}>
              <fieldset disabled={busy}>
                {credentials ? <>
                  {step === 'signup' && (
                    <>
                      <label htmlFor="name">Full Name</label>
                      <input
                        id="name"
                        name="name"
                        type="text"
                        autoComplete="name"
                        placeholder="Your full name"
                        maxLength={100}
                        required
                        value={name}
                        onChange={e => setName(e.target.value)}
                      />
                    </>
                  )}
                  <label htmlFor="email">DUET Student Email</label>
                  <input
                    id="email"
                    type="email"
                    autoComplete="username"
                    placeholder="student@students.duet.edu.pk"
                    maxLength={254}
                    required
                    value={email}
                    onChange={e => setEmail(e.target.value)}
                  />
                  <label htmlFor="password">Password</label>
                  <div className="password-field">
                    <input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      autoComplete={step === 'signup' ? 'new-password' : 'current-password'}
                      minLength={12}
                      maxLength={128}
                      placeholder="At least 12 characters"
                      required
                      value={password}
                      onChange={e => setPassword(e.target.value)}
                    />
                    <button
                      type="button"
                      className="password-toggle"
                      aria-label={showPassword ? 'Hide password' : 'Show password'}
                      aria-controls="password"
                      onClick={() => setShowPassword(v => !v)}
                    >
                      {showPassword ? 'Hide' : 'Show'}
                    </button>
                  </div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px' }}>
                    <p className="field-note" style={{ margin: 0 }}>
                      {step === 'signup' ? 'Must be @students.duet.edu.pk' : 'Next, we’ll ask for your authenticator code.'}
                    </p>
                    {step === 'login' && (
                      <button
                        type="button"
                        className="text-button"
                        style={{ margin: 0, fontSize: '11px' }}
                        onClick={() => change('forgot-password')}
                      >
                        Forgot password?
                      </button>
                    )}
                  </div>
                </> : <>
                  {step === 'enroll' && (
                    enrollment ? (
                      <div className="enrollment">
                        <img src={enrollment.qr} alt="Scan to add this account to your authenticator" width={220} height={220} />
                        <details>
                          <summary>Can’t scan? Enter a setup key</summary>
                          <code>{enrollment.secret}</code>
                          <p>Choose a time-based code: 6 digits, 30 seconds, SHA-1.</p>
                        </details>
                      </div>
                    ) : (
                      <button
                        type="button"
                        className="text-button"
                        onClick={async () => {
                          setBusy(true); setError('');
                          try { setEnrollment(await api('enroll')); }
                          catch (e: unknown) { setError(e instanceof Error ? e.message : 'Please try again.'); }
                          finally { setBusy(false); }
                        }}
                      >
                        Load setup QR code
                      </button>
                    )
                  )}
                  <label htmlFor="code">{step === 'recovery' ? 'Recovery code' : 'Authenticator code'}</label>
                  <input
                    id="code"
                    className="code-input"
                    type="text"
                    inputMode={step === 'recovery' ? 'text' : 'numeric'}
                    autoComplete="one-time-code"
                    pattern={step === 'recovery' ? '[a-fA-F0-9]{16}' : '[0-9]{6}'}
                    minLength={step === 'recovery' ? 16 : 6}
                    maxLength={step === 'recovery' ? 16 : 6}
                    placeholder={step === 'recovery' ? '16-character code' : '000000'}
                    required
                    value={code}
                    onChange={e => setCode(e.target.value.replace(/\s/g, ''))}
                  />
                </>}
                <button className="primary" type="submit" disabled={busy}>
                  {busy ? 'Please wait…' : step === 'signup' ? 'Create DUET account' : credentials ? 'Continue securely' : step === 'enroll' ? 'Connect authenticator' : 'Verify & sign in'}
                  <span aria-hidden="true">↗</span>
                </button>
              </fieldset>
            </form>
          )}

          {step === 'mfa' && <button disabled={busy} className="text-button" onClick={() => change('recovery')}>Lost access to your app? Use a recovery code</button>}
          {step === 'recovery' && <button disabled={busy} className="text-button" onClick={() => change('mfa')}>Use an authenticator code instead</button>}
          {step === 'saved' && (
            <>
              <div className="recovery-codes">{codes.map(item => <code key={item}>{item}</code>)}</div>
              <label className="checkbox"><input type="checkbox" checked={saved} onChange={e => setSaved(e.target.checked)} /> I saved my recovery codes in a safe place.</label>
              <button className="primary" disabled={!saved} onClick={() => { setCodes([]); change('session'); }}>Continue to account <span>↗</span></button>
            </>
          )}
          {['enroll', 'mfa', 'recovery'].includes(step) && <button className="text-button" disabled={busy} onClick={logout}>Back to sign in</button>}
          </>}
          <div className="card-footer"><span aria-hidden="true">◇</span> Exclusively for Dawood UET Students.</div>
        </>}
      </section>
    </div>
    <footer><span>SMALL STEP. STRONGER SECURITY.</span><span>Built for DUET Students.</span></footer>
  </main>;
}
