'use client';

import { FormEvent, useEffect, useState } from 'react';
import Dashboard from './dashboard';

type Step = 'login' | 'signup' | 'enroll' | 'mfa' | 'recovery' | 'saved' | 'session';
type Enrollment = { secret: string; qr: string };

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
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const [enrollment, setEnrollment] = useState<Enrollment | null>(null);
  const [codes, setCodes] = useState<string[]>([]);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    api('me').then(data => { setEmail(data.email); setName(data.name); setStep('session'); })
      .catch(() => {}).finally(() => setLoading(false));
  }, []);

  function change(next: Step) { setStep(next); setError(''); setCode(''); setShowPassword(false); }

  async function submit(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      if (step === 'login' || step === 'signup') {
        if (step === 'signup' && !name.trim()) throw new Error('Please enter your name.');
        const data = await api(step, step === 'signup' ? { name: name.trim(), email, password } : { email, password });
        setPassword('');
        change(data.step);
        if (data.step === 'enroll') setEnrollment(await api('enroll'));
      } else {
        const data = await api(step === 'enroll' ? 'enroll/confirm' : 'verify', { code, recovery: step === 'recovery' });
        setCode(''); setEnrollment(null);
        if (data.recovery_codes) { setName(data.name); setEmail(data.email); setCodes(data.recovery_codes); setSaved(false); change('saved'); }
        else { const profile = await api('me'); setEmail(profile.email); setName(profile.name); change('session'); }
      }
    } catch (e) { setError(e instanceof Error ? e.message : 'Please try again.'); }
    finally { setBusy(false); }
  }

  async function logout() {
    setBusy(true); setError('');
    try { await api('logout', {}); setEnrollment(null); setCodes([]); setPassword(''); setName(''); change('login'); }
    catch (e) { setError(e instanceof Error ? e.message : 'Sign out failed.'); }
    finally { setBusy(false); }
  }

  const credentials = step === 'login' || step === 'signup';
  const titles: Record<Step, string> = {
    login: 'Welcome back.', signup: 'Make yourself secure.', enroll: 'Meet your second layer.',
    mfa: 'One more little step.', recovery: 'Use a recovery code.', saved: 'Keep a spare key.', session: 'You’re securely signed in.',
  };
  const descriptions: Record<Step, string> = {
    login: 'Sign in to your account. Your authenticator takes care of the rest.',
    signup: 'Create an account, then connect your favorite authenticator.',
    enroll: 'Scan this QR code with Google Authenticator, Microsoft Authenticator, or another TOTP app.',
    mfa: 'Enter the six-digit code from your authenticator app. Codes refresh every 30 seconds.',
    recovery: 'Each recovery code works once. Your account password has already been verified.',
    saved: 'Save these eight one-use recovery codes somewhere private. They let you sign in if you lose your phone.',
    session: 'Your password and authenticator have both been verified.',
  };

  if (step === 'session') return <Dashboard name={name} email={email} onLogout={logout} busy={busy} error={error} />;

  return <main>
    <header><a className="brand" href="/" aria-label="Keyclock home"><span className="brandmark">k</span>keyclock<span className="branddot">®</span></a><span className="header-note"><span className="dot" /> A little more peace of mind</span></header>
    <div className="shell">
      <aside>
        <div className="eyebrow">YOUR ACCOUNT. YOUR ACCESS.</div>
        <h1>A second layer.<br /><em>A safer space.</em></h1>
        <p className="intro">A password opens the door.<br />Your authenticator makes sure it’s you.</p>
        <div className="illustration" aria-hidden="true"><div className="orbit one" /><div className="orbit two" /><div className="clock"><span className="clock-pin" /><span className="clock-hand" /><span className="clock-hand short" /></div><span className="mini-badge">✓</span><div className="floating-label">TIME-BASED. JUST FOR YOU.</div></div>
        <div className="aside-footer"><span className="small-star">✳</span><p>Works with your favorite authenticator.<br /><strong>One account. An extra layer of confidence.</strong></p></div>
      </aside>
      <section className="card" aria-labelledby="form-title" aria-busy={busy || loading}>
        <div className="card-top"><span className="eyebrow">SECURE ACCESS</span><span className="step-chip">{credentials ? '01 / 02' : '02 / 02'}</span></div>
        {loading ? <p role="status">Checking your session…</p> : <>
          {credentials && <div className="tabs"><button type="button" disabled={busy} className={step === 'login' ? 'active' : ''} onClick={() => change('login')}>Sign in</button><button type="button" disabled={busy} className={step === 'signup' ? 'active' : ''} onClick={() => change('signup')}>Create account</button></div>}
          <h2 id="form-title">{titles[step]}</h2><p className="description">{descriptions[step]}</p>
          {error && <div className="error" role="alert">{error}</div>}
          {(credentials || ['enroll', 'mfa', 'recovery'].includes(step)) && <form onSubmit={submit}>
            <fieldset disabled={busy}>
              {credentials ? <>
                {step === 'signup' && <><label htmlFor="name">Name</label><input id="name" name="name" type="text" autoComplete="name" placeholder="Your name" maxLength={100} required value={name} onChange={e => setName(e.target.value)} /></>}
                <label htmlFor="email">Email address</label><input id="email" type="email" autoComplete="username" placeholder="you@example.com" maxLength={254} required value={email} onChange={e => setEmail(e.target.value)} />
                <label htmlFor="password">Password</label><div className="password-field"><input id="password" type={showPassword ? 'text' : 'password'} autoComplete={step === 'signup' ? 'new-password' : 'current-password'} minLength={12} maxLength={128} placeholder="At least 12 characters" required value={password} onChange={e => setPassword(e.target.value)} /><button type="button" className="password-toggle" aria-label={showPassword ? 'Hide password' : 'Show password'} aria-controls="password" onClick={() => setShowPassword(value => !value)}>{showPassword ? 'Hide' : 'Show'}</button></div>
                <p className="field-note">{step === 'signup' ? 'Use a unique password with at least 12 characters.' : 'Next, we’ll ask for your authenticator code.'}</p>
              </> : <>
                {step === 'enroll' && (enrollment ? <div className="enrollment"><img src={enrollment.qr} alt="Scan to add this account to your authenticator" width={220} height={220} /><details><summary>Can’t scan? Enter a setup key</summary><code>{enrollment.secret}</code><p>Choose a time-based code: 6 digits, 30 seconds, SHA-1.</p></details></div> : <button type="button" className="text-button" onClick={async () => { setBusy(true); setError(''); try { setEnrollment(await api('enroll')); } catch (e) { setError(e instanceof Error ? e.message : 'Please try again.'); } finally { setBusy(false); } }}>Load setup QR code</button>)}
                <label htmlFor="code">{step === 'recovery' ? 'Recovery code' : 'Authenticator code'}</label><input id="code" className="code-input" type="text" inputMode={step === 'recovery' ? 'text' : 'numeric'} autoComplete="one-time-code" pattern={step === 'recovery' ? '[a-fA-F0-9]{16}' : '[0-9]{6}'} minLength={step === 'recovery' ? 16 : 6} maxLength={step === 'recovery' ? 16 : 6} placeholder={step === 'recovery' ? '16-character code' : '000000'} required value={code} onChange={e => setCode(e.target.value.replace(/\s/g, ''))} />
              </>}
              <button className="primary" type="submit">{busy ? 'Please wait…' : step === 'signup' ? 'Create account' : credentials ? 'Continue securely' : step === 'enroll' ? 'Connect authenticator' : 'Verify & sign in'}<span aria-hidden="true">↗</span></button>
            </fieldset>
          </form>}
          {step === 'mfa' && <button disabled={busy} className="text-button" onClick={() => change('recovery')}>Lost access to your app? Use a recovery code</button>}
          {step === 'recovery' && <button disabled={busy} className="text-button" onClick={() => change('mfa')}>Use an authenticator code instead</button>}
          {step === 'saved' && <><div className="recovery-codes">{codes.map(item => <code key={item}>{item}</code>)}</div><label className="checkbox"><input type="checkbox" checked={saved} onChange={e => setSaved(e.target.checked)} /> I saved my recovery codes in a safe place.</label><button className="primary" disabled={!saved} onClick={() => { setCodes([]); change('session'); }}>Continue to account <span>↗</span></button></>}
          {['enroll', 'mfa', 'recovery'].includes(step) && <button className="text-button" disabled={busy} onClick={logout}>Back to sign in</button>}
          <div className="card-footer"><span aria-hidden="true">◇</span> Your codes belong to you. Never share them.</div>
        </>}
      </section>
    </div>
    <footer><span>SMALL STEP. STRONGER SECURITY.</span><span>Built around your peace of mind.</span></footer>
  </main>;
}
