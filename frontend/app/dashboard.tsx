'use client';

import { FormEvent, useEffect, useRef, useState } from 'react';
import Members from './members';
import SecurityInspector from './security-inspector';
import {
  ShieldIcon,
  LockIcon,
  UnlockIcon,
  MailIcon,
  SendIcon,
  CheckIcon,
} from './icons';
import {
  decryptE2EEMessage,
  decryptPrivateKeyWithPassword,
  encryptE2EEMessage,
  encryptPrivateKeyWithPassword,
  exportPublicKey,
  generateE2EEKeyPair,
  importPublicKey,
  loadPrivateKeyFromSession,
  savePrivateKeyToSession,
} from './crypto';

type Message = { id: number; body: string; created_at: number; contact: { name: string; email: string }; isEncrypted?: boolean };
type Mailbox = { inbox: Message[]; sent: Message[]; inbox_count: number; sent_count: number };
type Props = { name: string; email: string; onLogout: () => Promise<void>; busy: boolean; error: string };

async function mailboxRequest(body?: { recipient: string; body: string; sender_body?: string }): Promise<Mailbox> {
  const response = await fetch('/api/auth/messages', {
    method: body ? 'POST' : 'GET', cache: 'no-store',
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const data = await response.json();
  if (!response.ok) throw new Error(data.detail || 'Could not load your messages. Please try again.');
  return data;
}

async function decryptMailbox(data: Mailbox, privKey: CryptoKey | null): Promise<Mailbox> {
  const decryptList = (list: Message[]) =>
    Promise.all(
      list.map(async item => {
        const { text, isEncrypted } = await decryptE2EEMessage(item.body, privKey);
        return { ...item, body: text, isEncrypted };
      })
    );
  const [inbox, sent] = await Promise.all([decryptList(data.inbox), decryptList(data.sent)]);
  return { ...data, inbox, sent };
}

export default function Dashboard({ name, email, onLogout, busy, error }: Props) {
  const [view, setView] = useState<'messages' | 'security'>('messages');
  const [rawMailbox, setRawMailbox] = useState<Mailbox | null>(null);
  const [mailbox, setMailbox] = useState<Mailbox | null>(null);
  const [folder, setFolder] = useState<'inbox' | 'sent'>('inbox');
  const [recipient, setRecipient] = useState('');
  const [body, setBody] = useState('');
  const [loading, setLoading] = useState(true);
  const [sending, setSending] = useState(false);
  const [loadError, setLoadError] = useState('');
  const [sendError, setSendError] = useState('');
  const [notice, setNotice] = useState('');
  const [userPrivateKey, setUserPrivateKey] = useState<CryptoKey | null>(null);
  const [unlockPassword, setUnlockPassword] = useState('');
  const [unlockError, setUnlockError] = useState('');
  const [unlocking, setUnlocking] = useState(false);
  const [showRekeyModal, setShowRekeyModal] = useState(false);
  const [rekeyTotp, setRekeyTotp] = useState('');
  const [rekeyBusy, setRekeyBusy] = useState(false);
  const composer = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    let active = true;
    (async () => {
      let key = await loadPrivateKeyFromSession();
      if (!active) return;
      if (key) setUserPrivateKey(key);

      try {
        const data = await mailboxRequest();
        if (!active) return;
        setRawMailbox(data);
        const decrypted = await decryptMailbox(data, key);
        if (!active) return;
        setMailbox(decrypted);
      } catch (e) {
        if (active) setLoadError(e instanceof Error ? e.message : 'Could not load messages.');
      } finally {
        if (active) setLoading(false);
      }
    })();
    return () => { active = false; };
  }, []);

  async function refresh(customKey?: CryptoKey | null) {
    setLoading(true); setLoadError('');
    const keyToUse = customKey !== undefined ? customKey : userPrivateKey;
    try {
      const data = await mailboxRequest();
      setRawMailbox(data);
      setMailbox(await decryptMailbox(data, keyToUse));
    }
    catch (e) { setLoadError(e instanceof Error ? e.message : 'Please try again.'); }
    finally { setLoading(false); }
  }

  async function handleUnlock(passwordToUse: string) {
    if (!passwordToUse) return;
    setUnlocking(true);
    setUnlockError('');
    try {
      const keysResponse = await fetch('/api/auth/keys', { cache: 'no-store' });
      const keysData = await keysResponse.json();
      if (!keysResponse.ok) throw new Error(keysData.detail || 'Could not fetch your encryption keys.');

      let privKey: CryptoKey;
      if (keysData.encrypted_private_key && keysData.public_key) {
        try {
          const res = await decryptPrivateKeyWithPassword(keysData.encrypted_private_key, passwordToUse);
          privKey = res.privateKey;
          await savePrivateKeyToSession(res.jwk);
          if (res.needsRewrap) {
            try {
              const rewrapped = await encryptPrivateKeyWithPassword(res.jwk, passwordToUse, 600000);
              await fetch('/api/auth/keys', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ public_key: keysData.public_key, encrypted_private_key: rewrapped }),
              });
            } catch {
              // Non-blocking rewrap
            }
          }
        } catch {
          throw new Error('Could not decrypt your private key. If you recently reset your password, your old key cannot be unlocked with the new password.');
        }
      } else {
        const keyPair = await generateE2EEKeyPair();
        const pubJwk = await exportPublicKey(keyPair.publicKey);
        const encPriv = await encryptPrivateKeyWithPassword(keyPair.privateKey, passwordToUse, 600000);
        const saveRes = await fetch('/api/auth/keys', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ public_key: pubJwk, encrypted_private_key: encPriv }),
        });
        if (!saveRes.ok) throw new Error('Could not initialize your encryption keys.');
        const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
        privKey = await crypto.subtle.importKey(
          'jwk',
          privJwk,
          { name: 'RSA-OAEP', hash: 'SHA-256' },
          false,
          ['decrypt']
        );
        await savePrivateKeyToSession(privJwk);
      }

      setUserPrivateKey(privKey);
      setUnlockPassword('');
      if (rawMailbox) {
        setMailbox(await decryptMailbox(rawMailbox, privKey));
      }
    } catch (err) {
      setUnlockError(err instanceof Error ? err.message : 'Incorrect password or failed to unlock keys.');
    } finally {
      setUnlocking(false);
    }
  }

  async function handleRekey() {
    if (!rekeyTotp || !unlockPassword) return;
    setRekeyBusy(true);
    setUnlockError('');
    try {
      const keyPair = await generateE2EEKeyPair();
      const pubJwk = await exportPublicKey(keyPair.publicKey);
      const encPriv = await encryptPrivateKeyWithPassword(keyPair.privateKey, unlockPassword, 600000);
      const res = await fetch('/api/auth/keys', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ public_key: pubJwk, encrypted_private_key: encPriv, code: rekeyTotp }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail || 'Could not replace keypair.');
      const privJwk = await crypto.subtle.exportKey('jwk', keyPair.privateKey);
      const privKey = await crypto.subtle.importKey(
        'jwk',
        privJwk,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        false,
        ['decrypt']
      );
      await savePrivateKeyToSession(privJwk);
      setUserPrivateKey(privKey);
      setUnlockPassword('');
      setShowRekeyModal(false);
      setRekeyTotp('');
      if (rawMailbox) setMailbox(await decryptMailbox(rawMailbox, privKey));
    } catch (err) {
      setUnlockError(err instanceof Error ? err.message : 'Failed to replace keypair.');
    } finally {
      setRekeyBusy(false);
    }
  }

  async function unlockKey(event: FormEvent) {
    event.preventDefault();
    await handleUnlock(unlockPassword);
  }

  async function send(event: FormEvent) {
    event.preventDefault(); setSendError(''); setNotice('');
    const recipientEmail = recipient.trim().toLowerCase();
    const plainText = body.trim();
    if (!plainText) { setSendError('Write a message before sending.'); return; }
    if (!recipientEmail) { setSendError('Specify a recipient.'); return; }

    const DUET_DOMAIN = '@students.duet.edu.pk';
    if (!recipientEmail.endsWith(DUET_DOMAIN)) {
      setSendError(`Recipient must be a DUET student with a ${DUET_DOMAIN} email address.`);
      return;
    }

    setSending(true);
    try {
      // 1. Fetch recipient's public key
      const recipientRes = await fetch(`/api/auth/keys?email=${encodeURIComponent(recipientEmail)}`, { cache: 'no-store' });
      const recipientKeyData = await recipientRes.json();
      if (!recipientRes.ok || !recipientKeyData.public_key) {
        throw new Error('Recipient has not configured E2EE keys yet. They must log in once to initialize encryption.');
      }
      const recipientPubKey = await importPublicKey(recipientKeyData.public_key);

      // 2. Fetch sender's public key
      const myRes = await fetch('/api/auth/keys', { cache: 'no-store' });
      const myKeyData = await myRes.json();
      if (!myRes.ok || !myKeyData.public_key) {
        throw new Error('Your encryption keys are not configured. Please unlock your key below first.');
      }
      const senderPubKey = await importPublicKey(myKeyData.public_key);

      // 3. Encrypt end-to-end
      const { recipientCiphertext, senderCiphertext } = await encryptE2EEMessage(plainText, recipientPubKey, senderPubKey);

      // 4. Send dual envelope to server
      await mailboxRequest({ recipient: recipientEmail, body: recipientCiphertext, sender_body: senderCiphertext });
      setBody(''); setRecipient(''); setNotice('End-to-end encrypted message sent.');
      await refresh();
    } catch (e) {
      setSendError(e instanceof Error ? e.message : 'Could not send your message.');
    } finally {
      setSending(false);
    }
  }

  return <main className="dashboard">
    <header>
      <a className="brand" href="/" aria-label="DUETCLOCK home"><span className="brandmark">D</span>DUETCLOCK<span className="branddot">®</span></a>
      <div className="dashboard-user">
        <span className="avatar">{(name || email).slice(0, 1).toUpperCase()}</span>
        <span>{name || email}</span>
        <button className="outline-button" disabled={busy || sending} onClick={onLogout}>{busy ? 'Signing out…' : 'Sign out'}</button>
      </div>
    </header>

    <section className="dashboard-welcome">
      <div>
        <p className="eyebrow">YOUR PERSONAL SPACE</p>
        <h1>Hello, {name || 'there'}.</h1>
        <p>A little space to connect. Send an encrypted note, keep in touch.</p>
      </div>
      <div style={{ display: 'flex', gap: '8px', flexWrap: 'wrap' }}>
        <span className="security-badge"><CheckIcon size={12} style={{ marginRight: 4, color: '#2b7a42' }} /> Authenticator protected</span>
        <span className="security-badge" title="End-to-End Encrypted via RSA-OAEP + AES-256-GCM"><LockIcon size={12} style={{ marginRight: 4, color: '#165c34' }} /> End-to-end encrypted</span>
      </div>
    </section>

    {error && <p className="error" role="alert">{error}</p>}

    <nav className="view-nav" aria-label="Dashboard sections">
      <button
        type="button"
        className={`view-nav-tab ${view === 'messages' ? 'active' : ''}`}
        onClick={() => setView('messages')}
      >
        <MailIcon size={14} style={{ marginRight: 6 }} /> Messages &amp; Direct Chat
      </button>
      <button
        type="button"
        className={`view-nav-tab ${view === 'security' ? 'active-security' : ''}`}
        onClick={() => setView('security')}
      >
        <ShieldIcon size={14} style={{ marginRight: 6 }} /> CIA Security &amp; Cryptography Inspector
      </button>
    </nav>

    {view === 'security' ? (
      <SecurityInspector
        name={name}
        email={email}
        userPrivateKey={userPrivateKey}
        rawMailbox={rawMailbox}
        decryptedMailbox={mailbox}
        onUnlock={handleUnlock}
        unlocking={unlocking}
        unlockError={unlockError}
      />
    ) : (
      <>
        {!userPrivateKey && (
          <section className="e2ee-unlock-banner" aria-label="Unlock encryption">
            <div>
              <strong><LockIcon size={14} style={{ marginRight: 6 }} /> End-to-End Encryption Key Locked</strong>
              <p>Enter your account password to unlock and decrypt your messages on this device.</p>
              <form className="e2ee-unlock-form" onSubmit={unlockKey}>
                <input
                  type="password"
                  className="e2ee-unlock-input"
                  placeholder="Your account password"
                  value={unlockPassword}
                  onChange={e => setUnlockPassword(e.target.value)}
                  disabled={unlocking}
                  required
                />
                <button type="submit" className="outline-button" disabled={unlocking || !unlockPassword}>
                  {unlocking ? 'Unlocking…' : 'Unlock Messages'}
                </button>
              </form>
              {unlockError && (
                <div style={{ marginTop: 8 }}>
                  <p className="error" style={{ margin: 0 }} role="alert">{unlockError}</p>
                  {unlockError.includes('reset your password') && (
                    !showRekeyModal ? (
                      <button
                        type="button"
                        className="text-button"
                        style={{ color: '#be2e15', marginTop: 8, fontSize: 13 }}
                        onClick={() => setShowRekeyModal(true)}
                      >
                        Reset encryption keypair (re-key with authenticator) →
                      </button>
                    ) : (
                      <div style={{ marginTop: 10, padding: 12, background: '#fff0e9', borderRadius: 8, border: '1px solid #ffd4c2' }}>
                        <p style={{ margin: '0 0 8px', fontSize: 12, color: '#be2e15', lineHeight: 1.4 }}>
                          <strong>Warning:</strong> Creating a new keypair lets you send and receive new messages, but previously received encrypted messages can no longer be decrypted.
                        </p>
                        <div style={{ display: 'flex', gap: 8, alignItems: 'center', flexWrap: 'wrap' }}>
                          <input
                            type="text"
                            inputMode="numeric"
                            placeholder="6-digit Authenticator code"
                            maxLength={6}
                            value={rekeyTotp}
                            onChange={e => setRekeyTotp(e.target.value.replace(/\D/g, '').slice(0, 6))}
                            style={{ width: 190, padding: '6px 10px', fontSize: 13, border: '1px solid var(--border)', borderRadius: 6 }}
                            disabled={rekeyBusy}
                          />
                          <button
                            type="button"
                            className="outline-button"
                            style={{ borderColor: '#be2e15', color: '#be2e15' }}
                            disabled={rekeyBusy || rekeyTotp.length !== 6 || !unlockPassword}
                            onClick={handleRekey}
                          >
                            {rekeyBusy ? 'Replacing…' : 'Generate New Keypair'}
                          </button>
                          <button
                            type="button"
                            className="text-button"
                            style={{ margin: 0, fontSize: 12 }}
                            disabled={rekeyBusy}
                            onClick={() => setShowRekeyModal(false)}
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )
                  )}
                </div>
              )}
            </div>
          </section>
        )}

        <section className="dashboard-stats" aria-label="Account overview">
          <div><span>Messages received</span><strong>{mailbox?.inbox_count ?? '—'}</strong><small>Your personal inbox</small></div>
          <div><span>Messages sent</span><strong>{mailbox?.sent_count ?? '—'}</strong><small>Conversations started</small></div>
          <div className="profile-stat"><span>Your account</span><strong>{name || 'Member'}</strong><small>{email}</small></div>
        </section>

        <div className="dashboard-grid">
          <section className="dashboard-panel" aria-labelledby="mailbox-title">
            <div className="panel-heading">
              <h2 id="mailbox-title">Your messages</h2>
              <button className="outline-button" disabled={loading || sending} onClick={() => refresh()}>{loading ? 'Loading…' : 'Refresh'}</button>
            </div>
            <div className="tabs mailbox-tabs" role="group" aria-label="Message folders">
              <button aria-pressed={folder === 'inbox'} className={folder === 'inbox' ? 'active' : ''} onClick={() => setFolder('inbox')}>Inbox</button>
              <button aria-pressed={folder === 'sent'} className={folder === 'sent' ? 'active' : ''} onClick={() => setFolder('sent')}>Sent</button>
            </div>
            {loadError && <p className="error" role="alert">{loadError}</p>}
            <div aria-busy={loading}>
              {!mailbox && loading ? (
                <p className="empty-mailbox" role="status">Loading your messages…</p>
              ) : mailbox && mailbox[folder].length === 0 ? (
                <div className="empty-mailbox">
                  <span aria-hidden="true" style={{ display: 'inline-block', marginBottom: 8 }}><MailIcon size={32} style={{ color: 'var(--muted)' }} /></span>
                  <h3>{folder === 'inbox' ? 'A fresh start.' : 'Your first hello starts here.'}</h3>
                  <p>{folder === 'inbox' ? 'Messages from other members will appear here. Share your account email so they can reach you.' : 'Send a message to another member using the form beside your inbox.'}</p>
                </div>
              ) : (
                <div className="message-list">
                  {mailbox?.[folder].map(message => (
                    <article className="message-item" key={message.id}>
                      <div className="message-meta">
                        <div>
                          <strong>
                            {folder === 'sent' ? 'To: ' : ''}{message.contact.name || message.contact.email}
                            {message.isEncrypted && <span className="e2ee-tag" title="End-to-End Encrypted"><LockIcon size={10} style={{ marginRight: 3 }} /> E2EE</span>}
                          </strong>
                          <small>{message.contact.email}</small>
                        </div>
                        <time dateTime={new Date(message.created_at * 1000).toISOString()}>
                          {new Date(message.created_at * 1000).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                        </time>
                      </div>
                      <p>{message.body}</p>
                      {folder === 'inbox' && (
                        <button
                          className="text-button"
                          disabled={sending}
                          onClick={() => {
                            setRecipient(message.contact.email);
                            setNotice('');
                            setSendError('');
                            composer.current?.focus();
                          }}
                        >
                          Reply ↗
                        </button>
                      )}
                    </article>
                  ))}
                </div>
              )}
            </div>
            {mailbox && mailbox[folder].length > 0 && <p className="mailbox-note">Showing the latest {mailbox[folder].length} messages. Refresh to check for new ones.</p>}
          </section>

          <section className="dashboard-panel compose-panel" aria-labelledby="compose-title">
            <div className="eyebrow">SAY HELLO</div>
            <h2 id="compose-title">Send a message.</h2>
            <div className="composer-e2ee-note"><LockIcon size={12} style={{ marginRight: 5 }} /> End-to-end encrypted (only recipient and you can read)</div>
            <p className="description">Reach another DUET student using their registered @students.duet.edu.pk email address.</p>
            <form onSubmit={send}>
              <fieldset disabled={sending || busy}>
                <label htmlFor="recipient">Recipient email</label>
                <input
                  id="recipient"
                  type="email"
                  required
                  maxLength={254}
                  placeholder="student@students.duet.edu.pk"
                  value={recipient}
                  onChange={e => setRecipient(e.target.value)}
                />
                <label htmlFor="message-body">Your message</label>
                <textarea
                  ref={composer}
                  id="message-body"
                  required
                  maxLength={2000}
                  rows={7}
                  placeholder="Start with a hello…"
                  value={body}
                  onChange={e => setBody(e.target.value)}
                />
                <div className="character-count">{body.length.toLocaleString()} / 2,000</div>
                {sendError && <p className="error" role="alert">{sendError}</p>}
                {notice && <p className="send-success" role="status"><CheckIcon size={13} style={{ marginRight: 4 }} /> {notice}</p>}
                <button type="submit" className="primary" disabled={!body.trim() || !recipient.trim()}>
                  {sending ? 'Encrypting & Sending…' : 'Send encrypted message'}
                  <span aria-hidden="true">↗</span>
                </button>
              </fieldset>
            </form>
            <p className="mailbox-note">Encrypted client-side. The server only stores ciphertext.</p>
          </section>
        </div>

        <Members
          disabled={sending || busy}
          onMessage={address => {
            setRecipient(address);
            setNotice('');
            setSendError('');
            composer.current?.focus();
            composer.current?.scrollIntoView({ block: 'center', behavior: 'auto' });
          }}
        />
      </>
    )}

    <footer>
      <span>SMALL STEP. STRONGER CONNECTIONS.</span>
      <span>Your space, a little more connected.</span>
    </footer>
  </main>;
}
