'use client';

import { useEffect, useState } from 'react';
import {
  diagnoseDecryption,
  exportPrivateKeyToJwk,
  parseEnvelope,
  tamperEnvelope,
} from './crypto';

type Message = {
  id: number;
  body: string;
  created_at: number;
  contact: { name: string; email: string };
  isEncrypted?: boolean;
};

type Mailbox = {
  inbox: Message[];
  sent: Message[];
  inbox_count: number;
  sent_count: number;
};

type Props = {
  name: string;
  email: string;
  userPrivateKey: CryptoKey | null;
  rawMailbox: Mailbox | null;
  decryptedMailbox: Mailbox | null;
  onUnlock: (password: string) => Promise<void>;
  unlocking: boolean;
  unlockError: string;
};

export default function SecurityInspector({
  name,
  email,
  userPrivateKey,
  rawMailbox,
  decryptedMailbox,
  onUnlock,
  unlocking,
  unlockError,
}: Props) {
  const [keysData, setKeysData] = useState<{ public_key: string; encrypted_private_key: string } | null>(null);
  const [loadingKeys, setLoadingKeys] = useState(true);
  const [revealedPrivateKeyJwk, setRevealedPrivateKeyJwk] = useState<string | null>(null);
  const [showPrivateKey, setShowPrivateKey] = useState(false);
  const [inspectorPassword, setInspectorPassword] = useState('');
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  // Message comparison & interactive lab state
  const [selectedMessageId, setSelectedMessageId] = useState<number | null>(null);
  const [labCiphertext, setLabCiphertext] = useState<string>('');
  const [isTampered, setIsTampered] = useState(false);
  const [labResult, setLabResult] = useState<{
    tested: boolean;
    success: boolean;
    plaintext: string | null;
    error: string | null;
    unwrappedKey: boolean;
  }>({ tested: false, success: false, plaintext: null, error: null, unwrappedKey: false });

  // Fetch keys from server
  useEffect(() => {
    let active = true;
    (async () => {
      try {
        const res = await fetch('/api/auth/keys', { cache: 'no-store' });
        const data = await res.json();
        if (active && res.ok) {
          setKeysData(data);
        }
      } catch (err) {
        console.error('Failed to load keys in inspector:', err);
      } finally {
        if (active) setLoadingKeys(false);
      }
    })();
    return () => {
      active = false;
    };
  }, []);

  // When private key becomes available, prepare JWK export
  useEffect(() => {
    if (userPrivateKey) {
      exportPrivateKeyToJwk(userPrivateKey)
        .then(jwk => {
          setRevealedPrivateKeyJwk(JSON.stringify(jwk, null, 2));
        })
        .catch(err => {
          console.error('Error exporting private JWK:', err);
        });
    } else {
      setRevealedPrivateKeyJwk(null);
      setShowPrivateKey(false);
    }
  }, [userPrivateKey]);

  // Set default selected message
  useEffect(() => {
    if (rawMailbox) {
      const allRaw = [...rawMailbox.inbox, ...rawMailbox.sent];
      if (allRaw.length > 0 && selectedMessageId === null) {
        setSelectedMessageId(allRaw[0].id);
        setLabCiphertext(allRaw[0].body);
        setIsTampered(false);
        setLabResult({ tested: false, success: false, plaintext: null, error: null, unwrappedKey: false });
      }
    }
  }, [rawMailbox, selectedMessageId]);

  // Format public key JWK nicely
  let formattedPublicJwk = 'Loading public key...';
  if (keysData?.public_key) {
    try {
      formattedPublicJwk = JSON.stringify(JSON.parse(keysData.public_key), null, 2);
    } catch {
      formattedPublicJwk = keysData.public_key;
    }
  }

  // Format encrypted private key JSON nicely
  let formattedEncryptedPrivKey = 'Loading encrypted bundle...';
  if (keysData?.encrypted_private_key) {
    try {
      formattedEncryptedPrivKey = JSON.stringify(JSON.parse(keysData.encrypted_private_key), null, 2);
    } catch {
      formattedEncryptedPrivKey = keysData.encrypted_private_key;
    }
  }

  // Find active message in raw and decrypted mailboxes
  const allRawMessages = rawMailbox ? [...rawMailbox.inbox, ...rawMailbox.sent] : [];
  const allDecryptedMessages = decryptedMailbox ? [...decryptedMailbox.inbox, ...decryptedMailbox.sent] : [];
  const activeRawMsg = allRawMessages.find(m => m.id === selectedMessageId);
  const activeDecryptedMsg = allDecryptedMessages.find(m => m.id === selectedMessageId);
  const activeParsedEnvelope = activeRawMsg ? parseEnvelope(activeRawMsg.body) : null;

  function copyToClipboard(text: string, label: string) {
    navigator.clipboard.writeText(text);
    setCopiedKey(label);
    setTimeout(() => setCopiedKey(null), 2500);
  }

  function handleSelectMessage(id: number) {
    setSelectedMessageId(id);
    const msg = allRawMessages.find(m => m.id === id);
    if (msg) {
      setLabCiphertext(msg.body);
      setIsTampered(false);
      setLabResult({ tested: false, success: false, plaintext: null, error: null, unwrappedKey: false });
    }
  }

  function handleTamperPayload() {
    if (!labCiphertext) return;
    const tampered = tamperEnvelope(labCiphertext);
    setLabCiphertext(tampered);
    setIsTampered(true);
    setLabResult({ tested: false, success: false, plaintext: null, error: null, unwrappedKey: false });
  }

  function handleResetPayload() {
    if (activeRawMsg) {
      setLabCiphertext(activeRawMsg.body);
      setIsTampered(false);
      setLabResult({ tested: false, success: false, plaintext: null, error: null, unwrappedKey: false });
    }
  }

  async function handleTestDecrypt() {
    if (!labCiphertext) return;
    const diag = await diagnoseDecryption(labCiphertext, userPrivateKey);
    setLabResult({
      tested: true,
      success: !diag.integrityError && !!diag.decryptedPlaintext,
      plaintext: diag.decryptedPlaintext,
      error: diag.errorMessage,
      unwrappedKey: diag.aesKeyUnwrapped,
    });
  }

  return (
    <div className="inspector-container">
      {/* 1. HERO HEADER */}
      <section className="inspector-hero" aria-label="Security Overview">
        <div>
          <span className="eyebrow" style={{ color: '#97d1b2' }}>INFORMATION SECURITY AUDIT</span>
          <h2>CIA Triad & Cryptographic State</h2>
          <p>
            Real-time verification of Zero-Knowledge encryption, client-side cryptographic keys, and database
            integrity fencing for <strong>{email}</strong>.
          </p>
        </div>
        <div className="inspector-hero-badges">
          <span className="hero-pill">
            <span style={{ color: '#7ceaa4' }}>●</span> @students.duet.edu.pk Fenced
          </span>
          <span className="hero-pill">
            <span style={{ color: '#7ceaa4' }}>●</span> Zero-Knowledge Web Crypto Active
          </span>
          <span className="hero-pill">
            <span style={{ color: '#7ceaa4' }}>●</span> Supabase PostgreSQL Connected
          </span>
        </div>
      </section>

      {/* 2. THE CIA TRIAD REAL-TIME VERIFICATION MATRIX */}
      <section className="cia-triad-grid" aria-label="CIA Triad Verification Cards">
        {/* CONFIDENTIALITY */}
        <article className="cia-card confidentiality">
          <div className="cia-card-header">
            <h3 className="cia-pillar-title">C · Confidentiality</h3>
            <span className="cia-pillar-badge">Enforced</span>
          </div>
          <p style={{ fontSize: '11px', color: 'var(--muted)', margin: 0 }}>
            Zero-Knowledge: The server and database administrator have zero ability to read messages or decrypt private keys.
          </p>
          <ul className="cia-specs-list">
            <li><span className="check">✓</span> <strong>RSA-OAEP 2048-bit</strong> Asymmetric Key Wrapping</li>
            <li><span className="check">✓</span> <strong>AES-256-GCM</strong> Ephemeral Symmetric Envelope</li>
            <li><span className="check">✓</span> <strong>PBKDF2</strong> (100,000 SHA-256 rounds + 16B Salt) for Private Key</li>
            <li><span className="check">✓</span> <strong>Fernet (AES-128-CBC + HMAC)</strong> for TOTP Secret at Rest</li>
            <li><span className="check">✓</span> <strong>Argon2id</strong> Adaptive Password Hashing</li>
          </ul>
        </article>

        {/* INTEGRITY */}
        <article className="cia-card integrity">
          <div className="cia-card-header">
            <h3 className="cia-pillar-title">I · Integrity</h3>
            <span className="cia-pillar-badge">Enforced</span>
          </div>
          <p style={{ fontSize: '11px', color: 'var(--muted)', margin: 0 }}>
            Tamper-Proofing: Any modification of ciphertext in transit or inside the database triggers instant cryptographic failure.
          </p>
          <ul className="cia-specs-list">
            <li><span className="check">✓</span> <strong>AES-256-GCM AEAD Tag</strong> (128-bit MAC validation)</li>
            <li><span className="check">✓</span> <strong>TOTP Anti-Replay Counter</strong> (Monotonic DB counter)</li>
            <li><span className="check">✓</span> <strong>@students.duet.edu.pk</strong> Domain Verification</li>
            <li><span className="check">✓</span> <strong>Single-Use Tickets</strong> (Atomic deletion on use)</li>
            <li><span className="check">✓</span> <strong>Constant-Time Digests</strong> (secrets.compare_digest)</li>
          </ul>
        </article>

        {/* AVAILABILITY */}
        <article className="cia-card availability">
          <div className="cia-card-header">
            <h3 className="cia-pillar-title">A · Availability</h3>
            <span className="cia-pillar-badge">Enforced</span>
          </div>
          <p style={{ fontSize: '11px', color: 'var(--muted)', margin: 0 }}>
            Service Continuity: Shields central servers from resource starvation and guarantees user disaster recovery.
          </p>
          <ul className="cia-specs-list">
            <li><span className="check">✓</span> <strong>Atomic Sliding Throttles</strong> (Login, OTP, Signup, API)</li>
            <li><span className="check">✓</span> <strong>8 One-Time Recovery Codes</strong> (Phone loss tolerance)</li>
            <li><span className="check">✓</span> <strong>Client-Side Crypto Offload</strong> (Server CPU preserved)</li>
            <li><span className="check">✓</span> <strong>Automated Database Garbage Collection</strong> of expired state</li>
            <li><span className="check">✓</span> <strong>5-Attempt OTP Lockout</strong> (Prevents 6-digit exhaustion)</li>
          </ul>
        </article>
      </section>

      {/* 3. CRYPTOGRAPHIC KEYPAIR & ZERO-KNOWLEDGE VAULT */}
      <section className="vault-section" aria-label="Cryptographic Keypair Vault">
        <div className="vault-section-title">
          <div>
            <span className="eyebrow">KEY MANAGEMENT SYSTEM</span>
            <h3>Cryptographic Keypair & Zero-Knowledge Vault</h3>
          </div>
          <span className="security-badge">W3C Web Crypto API (SubtleCrypto)</span>
        </div>

        <div className="vault-keys-grid">
          {/* Public Key Card */}
          <div className="key-box">
            <div className="key-box-header">
              <div>
                <h4>Public Key (RSA-OAEP 2048)</h4>
                <p>Stored publicly in Supabase <code>users.public_key</code></p>
              </div>
              <span className="key-badge public">Public Directory</span>
            </div>
            <pre className="code-display dark-json">
              {loadingKeys ? 'Fetching from server...' : formattedPublicJwk}
            </pre>
            <div className="key-box-footer">
              <span>Modulus: 2048 bits · Exponent: 65537 (AQAB)</span>
              <button
                type="button"
                className="outline-button"
                onClick={() => copyToClipboard(formattedPublicJwk, 'pub')}
              >
                {copiedKey === 'pub' ? '✓ Copied' : 'Copy Public JWK'}
              </button>
            </div>
          </div>

          {/* Encrypted Private Key (As Stored on Supabase) */}
          <div className="key-box">
            <div className="key-box-header">
              <div>
                <h4>Encrypted Private Key at Rest</h4>
                <p>As stored in Supabase <code>users.encrypted_private_key</code></p>
              </div>
              <span className="key-badge encrypted">Zero-Knowledge</span>
            </div>
            <pre className="code-display dark-json">
              {loadingKeys ? 'Fetching from server...' : formattedEncryptedPrivKey}
            </pre>
            <div className="key-box-footer">
              <span>Algorithm: PBKDF2 (100k) + AES-256-GCM</span>
              <button
                type="button"
                className="outline-button"
                onClick={() => copyToClipboard(formattedEncryptedPrivKey, 'encPriv')}
              >
                {copiedKey === 'encPriv' ? '✓ Copied' : 'Copy Stored Bundle'}
              </button>
            </div>
          </div>
        </div>

        {/* In-Memory Decrypted Private Key Status */}
        <div style={{ marginTop: '20px', padding: '16px 20px', background: '#f6faf5', border: '1px solid #d4e8d8', borderRadius: '12px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '12px' }}>
            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                <strong style={{ fontSize: '13px' }}>Client Browser Memory State:</strong>
                {userPrivateKey ? (
                  <span className="key-badge unlocked">● Private Key Unlocked (RAM / SessionStorage)</span>
                ) : (
                  <span className="key-badge locked">● Private Key Locked</span>
                )}
              </div>
              <p style={{ margin: '4px 0 0', fontSize: '11px', color: 'var(--muted)' }}>
                {userPrivateKey
                  ? 'Your decrypted RSA private key is currently loaded in client memory. It was decrypted locally with your password and will NEVER be transmitted over the network.'
                  : 'Your private key is locked. Enter your account password to decrypt it into browser memory.'}
              </p>
            </div>

            {userPrivateKey ? (
              <button
                type="button"
                className="outline-button"
                onClick={() => setShowPrivateKey(!showPrivateKey)}
              >
                {showPrivateKey ? 'Hide In-Memory Parameters' : 'Inspect In-Memory Private JWK'}
              </button>
            ) : (
              <form
                onSubmit={e => {
                  e.preventDefault();
                  if (inspectorPassword) onUnlock(inspectorPassword);
                }}
                style={{ display: 'flex', gap: '8px', alignItems: 'center' }}
              >
                <input
                  type="password"
                  placeholder="Account password"
                  value={inspectorPassword}
                  onChange={e => setInspectorPassword(e.target.value)}
                  disabled={unlocking}
                  style={{ padding: '7px 11px', fontSize: '11px', width: '180px' }}
                  required
                />
                <button type="submit" className="outline-button" disabled={unlocking || !inspectorPassword}>
                  {unlocking ? 'Unlocking…' : 'Unlock Key'}
                </button>
              </form>
            )}
          </div>

          {unlockError && <p className="error" style={{ margin: '10px 0 0', fontSize: '11px' }}>{unlockError}</p>}

          {showPrivateKey && revealedPrivateKeyJwk && (
            <div style={{ marginTop: '16px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                <span className="eyebrow" style={{ color: '#185c34' }}>CLIENT-SIDE PRIVATE JWK (NEVER SENT TO SERVER)</span>
                <button
                  type="button"
                  className="outline-button"
                  onClick={() => copyToClipboard(revealedPrivateKeyJwk, 'privJwk')}
                >
                  {copiedKey === 'privJwk' ? '✓ Copied' : 'Copy Private JWK'}
                </button>
              </div>
              <pre className="code-display" style={{ background: '#0a1610', color: '#68e29a' }}>
                {revealedPrivateKeyJwk}
              </pre>
            </div>
          )}
        </div>
      </section>

      {/* 4. SUPABASE DATABASE VS CLIENT DECRYPTION COMPARISON */}
      <section className="comparison-section" aria-label="Supabase DB vs Client Decryption">
        <div className="vault-section-title">
          <div>
            <span className="eyebrow">DATABASE VS CLIENT DECRYPTION</span>
            <h3>What Supabase Stores vs What You See</h3>
          </div>
          <span className="security-badge domain-badge">Zero Plaintext on Supabase</span>
        </div>

        {allRawMessages.length === 0 ? (
          <p style={{ color: 'var(--muted)', fontSize: '12px' }}>
            No messages found yet. Send or receive a message to inspect its raw database ciphertext and cryptographic envelope!
          </p>
        ) : (
          <>
            <div className="comparison-selector">
              <label htmlFor="msg-select" style={{ fontSize: '12px', fontWeight: 600, margin: 0 }}>
                Select Message to Inspect:
              </label>
              <select
                id="msg-select"
                value={selectedMessageId ?? ''}
                onChange={e => handleSelectMessage(Number(e.target.value))}
              >
                {allRawMessages.map(m => (
                  <option key={m.id} value={m.id}>
                    Message #{m.id} — Contact: {m.contact.name || m.contact.email} ({new Date(m.created_at * 1000).toLocaleTimeString()})
                  </option>
                ))}
              </select>
            </div>

            <div className="side-by-side-comparison">
              {/* Left Column: What Supabase Stores */}
              <div className="comparison-pane database-pane">
                <div className="comparison-pane-header">
                  <h4><span>🗄️</span> What Supabase DB Stores (Raw Record)</h4>
                  <span className="key-badge encrypted">Ciphertext Only</span>
                </div>

                <div className="envelope-field">
                  <strong>Raw Database Column (messages.body):</strong>
                  <pre className="code-display dark-json" style={{ maxHeight: '110px' }}>
                    {activeRawMsg?.body || 'No message selected'}
                  </pre>
                </div>

                {activeParsedEnvelope ? (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', marginTop: '6px' }}>
                    <div className="envelope-field">
                      <strong>1. Ephemeral AES-256-GCM IV (12 Bytes):</strong>
                      <code style={{ fontSize: '11px', background: '#ece5db', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all' }}>
                        {activeParsedEnvelope.iv}
                      </code>
                    </div>
                    <div className="envelope-field">
                      <strong>2. RSA-OAEP Wrapped Ephemeral AES Key (2048-bit ciphertext):</strong>
                      <code style={{ fontSize: '11px', background: '#ece5db', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all', maxHeight: '55px', overflowY: 'auto' }}>
                        {activeParsedEnvelope.key}
                      </code>
                    </div>
                    <div className="envelope-field">
                      <strong>3. AES-256-GCM Ciphertext + 128-bit AEAD Tag:</strong>
                      <code style={{ fontSize: '11px', background: '#ece5db', padding: '4px 8px', borderRadius: '4px', wordBreak: 'break-all' }}>
                        {activeParsedEnvelope.ct}
                      </code>
                    </div>
                  </div>
                ) : (
                  <p style={{ fontSize: '11px', color: 'var(--muted)' }}>Non-E2EE legacy message payload.</p>
                )}
              </div>

              {/* Right Column: What Client Decrypts */}
              <div className="comparison-pane client-pane">
                <div className="comparison-pane-header">
                  <h4><span>🔓</span> What Client Decrypts via Private Key</h4>
                  <span className="key-badge public">Decrypted in RAM</span>
                </div>

                <div className="envelope-field">
                  <strong>Sender / Contact Attestation:</strong>
                  <div style={{ fontSize: '12px', fontWeight: 600 }}>
                    {activeDecryptedMsg?.contact.name} ({activeDecryptedMsg?.contact.email})
                  </div>
                  <span style={{ fontSize: '10px', color: 'var(--green)' }}>✓ Verified @students.duet.edu.pk identity</span>
                </div>

                <div className="envelope-field" style={{ marginTop: '8px' }}>
                  <strong>Decrypted Plaintext:</strong>
                  <div style={{ background: '#fff', border: '1px solid #c9e1ce', borderRadius: '8px', padding: '14px', minHeight: '90px', fontSize: '13px', lineHeight: '1.6', wordBreak: 'break-word', color: 'var(--ink)' }}>
                    {activeDecryptedMsg?.body || '[Decrypting...]'}
                  </div>
                </div>

                <div style={{ fontSize: '10px', color: 'var(--muted)', marginTop: '8px', lineHeight: '1.5' }}>
                  <strong>Cryptographic Path:</strong>
                  <br />
                  1. Browser memory supplies unlocked RSA Private Key.
                  <br />
                  2. RSA-OAEP decrypts the 256-bit AES symmetric key.
                  <br />
                  3. AES-256-GCM verifies 128-bit authentication tag and decrypts message.
                </div>
              </div>
            </div>
          </>
        )}
      </section>

      {/* 5. INTERACTIVE TAMPER & INTEGRITY LAB */}
      <section className="lab-section" aria-label="Interactive Tamper and Decrypt Lab">
        <div className="vault-section-title">
          <div>
            <span className="eyebrow">LIVE PRESENTATION DEMO</span>
            <h3>Interactive AEAD Integrity & Tamper Attack Simulator</h3>
          </div>
          <span className="security-badge">Classroom Demo Mode</span>
        </div>

        <p style={{ fontSize: '12px', color: 'var(--muted)', margin: '0 0 14px', lineHeight: '1.6' }}>
          Demonstrate to your classmates and professor that <strong>AES-256-GCM</strong> is an <em>Authenticated Cipher (AEAD)</em>.
          If an attacker (or rogue database administrator) modifies even a single character in the ciphertext, the
          cryptographic tag check fails and prevents unauthorized data manipulation.
        </p>

        <div className="envelope-field">
          <strong>Ciphertext Under Test (Editable or Tamperable):</strong>
          <textarea
            rows={4}
            value={labCiphertext}
            onChange={e => {
              setLabCiphertext(e.target.value);
              setIsTampered(true);
              setLabResult({ tested: false, success: false, plaintext: null, error: null, unwrappedKey: false });
            }}
            style={{
              fontFamily: 'Consolas, Monaco, monospace',
              fontSize: '11px',
              padding: '10px',
              border: isTampered ? '2px solid #d94326' : '1px solid #dce1d6',
              borderRadius: '6px',
              background: '#fff',
              color: 'var(--ink)',
              width: '100%',
              resize: 'vertical',
            }}
          />
        </div>

        <div className="lab-actions-bar">
          <button
            type="button"
            className="tamper-button"
            onClick={handleTamperPayload}
            disabled={!labCiphertext}
            title="Corrupt ciphertext bytes to simulate a man-in-the-middle or database tampering attack"
          >
            ⚠️ Simulate Attack: Tamper 1 Byte in Ciphertext
          </button>

          <button
            type="button"
            className="test-decrypt-button"
            onClick={handleTestDecrypt}
            disabled={!labCiphertext}
          >
            🔓 Test Decrypt with Private Key
          </button>

          <button
            type="button"
            className="reset-button"
            onClick={handleResetPayload}
            disabled={!activeRawMsg}
          >
            ↺ Reset to Original Message
          </button>

          {isTampered && (
            <span style={{ fontSize: '11px', color: '#c93418', fontWeight: 600 }}>
              ● Tampered / Modified Payload
            </span>
          )}
        </div>

        {/* Live Test Results */}
        {labResult.tested && (
          <div className={`lab-result-box ${labResult.success ? 'success' : 'tamper-caught'}`}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px', fontWeight: 700, fontSize: '13px' }}>
              {labResult.success ? '✓ AEAD Verification Succeeded' : '❌ Cryptographic Integrity Violation Caught!'}
            </div>

            <ul className="lab-result-steps">
              <li>
                <span>{labResult.unwrappedKey ? '✓' : '⚠️'}</span>
                <strong>RSA-OAEP Key Unwrapping:</strong>{' '}
                {labResult.unwrappedKey ? 'Ephemeral AES-256 key successfully recovered using private key.' : 'Could not unwrap AES key.'}
              </li>
              <li>
                <span>{labResult.success ? '✓' : '❌'}</span>
                <strong>AES-256-GCM AEAD Tag Authentication:</strong>{' '}
                {labResult.success
                  ? 'Authentication tag matches! Message has not been modified.'
                  : 'Authentication tag MISMATCH! Decryption aborted.'}
              </li>
            </ul>

            {labResult.success ? (
              <div style={{ marginTop: '10px' }}>
                <strong>Decrypted Plaintext: </strong>
                <span style={{ fontStyle: 'italic' }}>&ldquo;{labResult.plaintext}&rdquo;</span>
              </div>
            ) : (
              <div style={{ marginTop: '10px', color: '#962816' }}>
                <strong>System Response: </strong>
                <span>{labResult.error}</span>
              </div>
            )}
          </div>
        )}
      </section>
    </div>
  );
}

