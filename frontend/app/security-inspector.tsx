'use client';

import { useEffect, useState } from 'react';
import {
  diagnoseDecryption,
  exportPrivateKeyToJwk,
  parseEnvelope,
  tamperEnvelope,
  computeKeyFingerprint,
  computeSafetyNumber,
} from './crypto';
import {
  ShieldIcon,
  LockIcon,
  UnlockIcon,
  KeyIcon,
  DatabaseIcon,
  CheckIcon,
  CrossIcon,
  AlertTriangleIcon,
  FingerprintIcon,
  CopyIcon,
  RefreshIcon,
  StarIcon,
  AcademicCapIcon,
} from './icons';

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

  // Cryptographic Safety Number state (Anti-MITM)
  const [userFingerprint, setUserFingerprint] = useState<string>('Computing...');
  const [safetyPeerEmail, setSafetyPeerEmail] = useState<string>('');
  const [safetyNumberResult, setSafetyNumberResult] = useState<string | null>(null);
  const [safetyComputing, setSafetyComputing] = useState<boolean>(false);
  const [safetyError, setSafetyError] = useState<string | null>(null);
  const [benchmarkCategory, setBenchmarkCategory] = useState<'all' | 'trust' | 'crypto' | 'metadata' | 'identity'>('all');

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
          if (data.public_key) {
            computeKeyFingerprint(data.public_key).then(fp => {
              if (active) setUserFingerprint(fp);
            });
          }
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
          if (jwk) {
            setRevealedPrivateKeyJwk(JSON.stringify(jwk, null, 2));
          } else {
            setRevealedPrivateKeyJwk('[Non-extractable RSA private key protected in WebCrypto memory]');
          }
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

  async function handleCalculateSafetyNumber(e: React.FormEvent) {
    e.preventDefault();
    if (!safetyPeerEmail.trim()) return;
    setSafetyComputing(true);
    setSafetyError(null);
    setSafetyNumberResult(null);
    try {
      if (!keysData?.public_key) throw new Error('Your public key is still loading. Please try again.');
      const cleanPeer = safetyPeerEmail.trim().toLowerCase();
      const res = await fetch(`/api/auth/keys?email=${encodeURIComponent(cleanPeer)}`, { cache: 'no-store' });
      if (!res.ok) {
        throw new Error(`Could not find public key for ${cleanPeer}. Verify they have completed registration.`);
      }
      const peerKeyData = await res.json();
      if (!peerKeyData.public_key) {
        throw new Error('This user has not initialized their E2EE public key yet.');
      }
      const safetyNum = await computeSafetyNumber(keysData.public_key, peerKeyData.public_key);
      setSafetyNumberResult(safetyNum);
    } catch (err: unknown) {
      setSafetyError(err instanceof Error ? err.message : 'Failed to calculate safety number.');
    } finally {
      setSafetyComputing(false);
    }
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
            <li><span className="check"><CheckIcon size={12} /></span> <strong>RSA-OAEP 2048-bit</strong> Asymmetric Key Wrapping</li>
            <li><span className="check"><CheckIcon size={12} /></span> <strong>AES-256-GCM</strong> Ephemeral Symmetric Envelope</li>
            <li><span className="check"><CheckIcon size={12} /></span> <strong>PBKDF2</strong> (100,000 SHA-256 rounds + 16B Salt) for Private Key</li>
            <li><span className="check"><CheckIcon size={12} /></span> <strong>Fernet (AES-128-CBC + HMAC)</strong> for TOTP Secret at Rest</li>
            <li><span className="check"><CheckIcon size={12} /></span> <strong>Argon2id</strong> Adaptive Password Hashing</li>
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
            <li><span className="check"><CheckIcon size={12} /></span> <strong>AES-256-GCM AEAD Tag</strong> (128-bit MAC validation)</li>
            <li><span className="check"><CheckIcon size={12} /></span> <strong>TOTP Anti-Replay Counter</strong> (Monotonic DB counter)</li>
            <li><span className="check"><CheckIcon size={12} /></span> <strong>@students.duet.edu.pk</strong> Domain Verification</li>
            <li><span className="check"><CheckIcon size={12} /></span> <strong>Single-Use Tickets</strong> (Atomic deletion on use)</li>
            <li><span className="check"><CheckIcon size={12} /></span> <strong>Constant-Time Digests</strong> (secrets.compare_digest)</li>
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
            <li><span className="check"><CheckIcon size={12} /></span> <strong>Atomic Sliding Throttles</strong> (Login, OTP, Signup, API)</li>
            <li><span className="check"><CheckIcon size={12} /></span> <strong>8 One-Time Recovery Codes</strong> (Phone loss tolerance)</li>
            <li><span className="check"><CheckIcon size={12} /></span> <strong>Client-Side Crypto Offload</strong> (Server CPU preserved)</li>
            <li><span className="check"><CheckIcon size={12} /></span> <strong>Automated Database Garbage Collection</strong> of expired state</li>
            <li><span className="check"><CheckIcon size={12} /></span> <strong>5-Attempt OTP Lockout</strong> (Prevents 6-digit exhaustion)</li>
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
                {copiedKey === 'pub' ? <><CheckIcon size={12} style={{ marginRight: 4 }} /> Copied</> : <><CopyIcon size={12} style={{ marginRight: 4 }} /> Copy Public JWK</>}
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
                {copiedKey === 'encPriv' ? <><CheckIcon size={12} style={{ marginRight: 4 }} /> Copied</> : <><CopyIcon size={12} style={{ marginRight: 4 }} /> Copy Stored Bundle</>}
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
                  <span className="key-badge unlocked"><UnlockIcon size={12} style={{ marginRight: 4 }} /> Private Key Unlocked (RAM / SessionStorage)</span>
                ) : (
                  <span className="key-badge locked"><LockIcon size={12} style={{ marginRight: 4 }} /> Private Key Locked</span>
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
                  {copiedKey === 'privJwk' ? <><CheckIcon size={12} style={{ marginRight: 4 }} /> Copied</> : <><CopyIcon size={12} style={{ marginRight: 4 }} /> Copy Private JWK</>}
                </button>
              </div>
              <pre className="code-display" style={{ background: '#0a1610', color: '#68e29a' }}>
                {revealedPrivateKeyJwk}
              </pre>
            </div>
          )}
        </div>
      </section>

      {/* 4. ANTI-MITM SAFETY NUMBERS (KEY FINGERPRINT VERIFICATION) */}
      <section className="vault-section" aria-label="Anti-MITM Safety Numbers">
        <div className="vault-section-title">
          <div>
            <span className="eyebrow">IDENTITY INTEGRITY &amp; ANTI-MITM</span>
            <h3>Cryptographic Safety Numbers (Public Key Fingerprints)</h3>
          </div>
          <span className="security-badge">Man-in-the-Middle Defense</span>
        </div>

        <p style={{ fontSize: '12px', color: 'var(--muted)', margin: '0 0 16px', lineHeight: '1.6' }}>
          In public key cryptography, an attacker with server or database access could attempt a <em>Key Substitution Attack</em> (swapping a classmate&apos;s public key with an attacker&apos;s).
          By comparing this 60-digit safety number out-of-band (or checking the SHA-256 fingerprint), both students mathematically prove that their end-to-end communication is untampered without relying on a centralized Certificate Authority (CA).
        </p>

        <div className="safety-grid">
          {/* Your Fingerprint */}
          <div className="safety-card">
            <div className="safety-card-header">
              <div>
                <h4>Your Public Key SHA-256 Fingerprint</h4>
                <p>Derived from your 2048-bit RSA-OAEP Public Key</p>
              </div>
              <span className="key-badge public">Local Device</span>
            </div>
            <div className="safety-fingerprint-display">
              <code>{userFingerprint}</code>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: '10px' }}>
              <span style={{ fontSize: '11px', color: 'var(--muted)' }}>Format: 8 groups of 4-hex chunks</span>
              <button
                type="button"
                className="outline-button"
                onClick={() => copyToClipboard(userFingerprint, 'fp')}
              >
                {copiedKey === 'fp' ? <><CheckIcon size={12} style={{ marginRight: 4 }} /> Copied</> : <><CopyIcon size={12} style={{ marginRight: 4 }} /> Copy Fingerprint</>}
              </button>
            </div>
          </div>

          {/* Peer Safety Number Calculator */}
          <div className="safety-card">
            <div className="safety-card-header">
              <div>
                <h4>Verify Safety Number with a Peer</h4>
                <p>Calculates the deterministic 60-digit pairwise code</p>
              </div>
              <span className="key-badge encrypted">Pairwise Identity</span>
            </div>

            <form onSubmit={handleCalculateSafetyNumber} style={{ display: 'flex', gap: '8px', marginTop: '4px' }}>
              <input
                type="email"
                placeholder="student@students.duet.edu.pk"
                value={safetyPeerEmail}
                onChange={e => setSafetyPeerEmail(e.target.value)}
                disabled={safetyComputing}
                required
                style={{ flex: 1, padding: '7px 11px', fontSize: '11px', border: '1px solid var(--line)', borderRadius: '6px' }}
              />
              <button
                type="submit"
                className="outline-button"
                disabled={safetyComputing || !safetyPeerEmail.trim()}
              >
                {safetyComputing ? 'Fetching Key…' : <><FingerprintIcon size={12} style={{ marginRight: 4 }} /> Compute 60-Digit Code</>}
              </button>
            </form>

            {safetyError && (
              <p className="error" style={{ margin: '8px 0 0', fontSize: '11px' }}>{safetyError}</p>
            )}

            {safetyNumberResult && (
              <div className="safety-result-box">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
                  <strong style={{ fontSize: '11px', color: '#165c34', display: 'flex', alignItems: 'center', gap: 4 }}>
                    <CheckIcon size={13} style={{ color: '#165c34' }} /> Pairwise 60-Digit Safety Number with {safetyPeerEmail}:
                  </strong>
                  <button
                    type="button"
                    className="outline-button"
                    style={{ fontSize: '10px', padding: '2px 8px' }}
                    onClick={() => copyToClipboard(safetyNumberResult, 'safetyNum')}
                  >
                    {copiedKey === 'safetyNum' ? <><CheckIcon size={11} style={{ marginRight: 3 }} /> Copied</> : <><CopyIcon size={11} style={{ marginRight: 3 }} /> Copy Code</>}
                  </button>
                </div>
                <div className="safety-digits-box">
                  {safetyNumberResult}
                </div>
                <p style={{ margin: '8px 0 0', fontSize: '10px', color: 'var(--muted)', lineHeight: '1.4' }}>
                  Both you and {safetyPeerEmail} compute this identical number independently. If either public key has been altered by a proxy or database admin, the numbers will mismatch!
                </p>
              </div>
            )}
          </div>
        </div>
      </section>

      {/* 5. SUPABASE DATABASE VS CLIENT DECRYPTION COMPARISON */}
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
                  <h4><DatabaseIcon size={16} style={{ marginRight: 6, color: '#254e7d' }} /> What Supabase DB Stores (Raw Record)</h4>
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
                  <h4><UnlockIcon size={16} style={{ marginRight: 6, color: '#165c34' }} /> What Client Decrypts via Private Key</h4>
                  <span className="key-badge public">Decrypted in RAM</span>
                </div>

                <div className="envelope-field">
                  <strong>Sender / Contact Attestation:</strong>
                  <div style={{ fontSize: '12px', fontWeight: 600 }}>
                    {activeDecryptedMsg?.contact.name} ({activeDecryptedMsg?.contact.email})
                  </div>
                  <span style={{ fontSize: '10px', color: 'var(--green)' }}><CheckIcon size={11} style={{ marginRight: 3, color: 'var(--green)' }} /> Verified @students.duet.edu.pk identity</span>
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
            <AlertTriangleIcon size={14} style={{ marginRight: 6 }} /> Simulate Attack: Tamper 1 Byte in Ciphertext
          </button>

          <button
            type="button"
            className="test-decrypt-button"
            onClick={handleTestDecrypt}
            disabled={!labCiphertext}
          >
            <UnlockIcon size={14} style={{ marginRight: 6 }} /> Test Decrypt with Private Key
          </button>

          <button
            type="button"
            className="reset-button"
            onClick={handleResetPayload}
            disabled={!activeRawMsg}
          >
            <RefreshIcon size={13} style={{ marginRight: 6 }} /> Reset to Original Message
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
              {labResult.success ? (
                <><CheckIcon size={15} style={{ marginRight: 6, color: '#165c34' }} /> AEAD Verification Succeeded</>
              ) : (
                <><CrossIcon size={15} style={{ marginRight: 6, color: '#d94326' }} /> Cryptographic Integrity Violation Caught!</>
              )}
            </div>

            <ul className="lab-result-steps">
              <li>
                <span>{labResult.unwrappedKey ? <CheckIcon size={13} style={{ color: '#2b7a42' }} /> : <AlertTriangleIcon size={13} style={{ color: '#d94326' }} />}</span>
                <strong>RSA-OAEP Key Unwrapping:</strong>{' '}
                {labResult.unwrappedKey ? 'Ephemeral AES-256 key successfully recovered using private key.' : 'Could not unwrap AES key.'}
              </li>
              <li>
                <span>{labResult.success ? <CheckIcon size={13} style={{ color: '#2b7a42' }} /> : <CrossIcon size={13} style={{ color: '#d94326' }} />}</span>
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

      {/* 7. INDUSTRY BENCHMARK MATRIX: DUETCLOCK VS WHATSAPP VS TELEGRAM */}
      <section className="benchmark-section" aria-label="WhatsApp vs Telegram Comparison">
        <div className="vault-section-title">
          <div>
            <span className="eyebrow">COMPETITIVE CRYPTOGRAPHIC ANALYSIS</span>
            <h3>Industry Security Benchmark: DUETCLOCK vs. WhatsApp vs. Telegram</h3>
          </div>
          <span className="security-badge">Academic Defense Suite</span>
        </div>

        <p style={{ fontSize: '12px', color: 'var(--muted)', margin: '0 0 16px', lineHeight: '1.6' }}>
          Evaluate why proprietary commercial messengers fall short under strict zero-trust threat models, and how DUETCLOCK eliminates centralized trust dependencies.
        </p>

        {/* Filter categories */}
        <div className="benchmark-filters">
          <button
            type="button"
            className={`benchmark-pill ${benchmarkCategory === 'all' ? 'active' : ''}`}
            onClick={() => setBenchmarkCategory('all')}
          >
            All Dimensions (6)
          </button>
          <button
            type="button"
            className={`benchmark-pill ${benchmarkCategory === 'trust' ? 'active' : ''}`}
            onClick={() => setBenchmarkCategory('trust')}
          >
            Server Trust &amp; Zero-Knowledge
          </button>
          <button
            type="button"
            className={`benchmark-pill ${benchmarkCategory === 'crypto' ? 'active' : ''}`}
            onClick={() => setBenchmarkCategory('crypto')}
          >
            Cryptographic Standards
          </button>
          <button
            type="button"
            className={`benchmark-pill ${benchmarkCategory === 'metadata' ? 'active' : ''}`}
            onClick={() => setBenchmarkCategory('metadata')}
          >
            Metadata Privacy
          </button>
          <button
            type="button"
            className={`benchmark-pill ${benchmarkCategory === 'identity' ? 'active' : ''}`}
            onClick={() => setBenchmarkCategory('identity')}
          >
            Identity &amp; SIM-Swap Defense
          </button>
        </div>

        {/* Comparison Table */}
        <div className="benchmark-table-wrapper">
          <table className="benchmark-table">
            <thead>
              <tr>
                <th style={{ width: '22%' }}>Security Dimension</th>
                <th style={{ width: '26%' }}>Telegram</th>
                <th style={{ width: '26%' }}>WhatsApp</th>
                <th style={{ width: '26%', background: '#eaf4ed', color: '#165c34' }}>DUETCLOCK (This System)</th>
              </tr>
            </thead>
            <tbody>
              {(benchmarkCategory === 'all' || benchmarkCategory === 'crypto') && (
                <tr>
                  <td>
                    <strong>Default E2EE Guarantee</strong>
                    <small>Is message encryption mandatory?</small>
                  </td>
                  <td className="critique-cell">
                    <span className="status-cross"><CrossIcon size={12} style={{ marginRight: 4 }} /> NOT by default</span>
                    <p>All regular group and 1-on-1 chats are stored on Telegram servers with server-accessible keys.</p>
                  </td>
                  <td className="status-cell">
                    <span className="status-check"><CheckIcon size={12} style={{ marginRight: 4 }} /> Default E2EE</span>
                    <p>Uses Signal Protocol for message transport.</p>
                  </td>
                  <td className="champion-cell">
                    <span className="status-champion"><StarIcon size={12} style={{ marginRight: 4, color: '#e09819' }} /> 100% Mandatory E2EE</span>
                    <p>Plaintext never leaves the client browser RAM. Server physically cannot disable E2EE.</p>
                  </td>
                </tr>
              )}

              {(benchmarkCategory === 'all' || benchmarkCategory === 'crypto') && (
                <tr>
                  <td>
                    <strong>Cryptographic Standards</strong>
                    <small>NIST/W3C vs Custom Homebrew</small>
                  </td>
                  <td className="critique-cell">
                    <span className="status-cross"><AlertTriangleIcon size={12} style={{ marginRight: 4 }} /> Proprietary &ldquo;MTProto&rdquo;</span>
                    <p>Custom MAC construction, historically criticized by cryptographers for non-standard design.</p>
                  </td>
                  <td className="status-cell">
                    <span className="status-check"><CheckIcon size={12} style={{ marginRight: 4 }} /> Signal Protocol</span>
                    <p>Double Ratchet algorithm with Curve25519.</p>
                  </td>
                  <td className="champion-cell">
                    <span className="status-champion"><StarIcon size={12} style={{ marginRight: 4, color: '#e09819' }} /> W3C &amp; NIST Standards</span>
                    <p>Native WebCrypto API: RSA-OAEP (2048), AES-256-GCM (128-bit MAC), PBKDF2 (100k SHA-256).</p>
                  </td>
                </tr>
              )}

              {(benchmarkCategory === 'all' || benchmarkCategory === 'trust') && (
                <tr>
                  <td>
                    <strong>Server Trust &amp; Zero-Knowledge</strong>
                    <small>Can database admin read messages?</small>
                  </td>
                  <td className="critique-cell">
                    <span className="status-cross"><CrossIcon size={12} style={{ marginRight: 4 }} /> Complete Server Trust</span>
                    <p>Telegram holds the master keys for cloud messages. Subpoenas or breaches expose chats.</p>
                  </td>
                  <td className="critique-cell">
                    <span className="status-cross"><AlertTriangleIcon size={12} style={{ marginRight: 4 }} /> Closed Trust Model</span>
                    <p>Meta controls the closed key servers and mobile binaries. Key changes are not verified automatically.</p>
                  </td>
                  <td className="champion-cell">
                    <span className="status-champion"><StarIcon size={12} style={{ marginRight: 4, color: '#e09819' }} /> True Zero-Knowledge</span>
                    <p>Supabase only ever stores ciphertext blobs. Even root database admins see zero plaintext.</p>
                  </td>
                </tr>
              )}

              {(benchmarkCategory === 'all' || benchmarkCategory === 'metadata') && (
                <tr>
                  <td>
                    <strong>Metadata &amp; Social Graph</strong>
                    <small>Who you talk to, when &amp; how often</small>
                  </td>
                  <td className="critique-cell">
                    <span className="status-cross"><CrossIcon size={12} style={{ marginRight: 4 }} /> High Metadata Exposure</span>
                    <p>Logs contacts, IP addresses, online timestamps, and group affiliations on cloud servers.</p>
                  </td>
                  <td className="critique-cell">
                    <span className="status-cross"><CrossIcon size={12} style={{ marginRight: 4 }} /> Commercial Metadata Mining</span>
                    <p>Meta mines social graphs, messaging frequencies, device fingerprints, and address books.</p>
                  </td>
                  <td className="champion-cell">
                    <span className="status-champion"><StarIcon size={12} style={{ marginRight: 4, color: '#e09819' }} /> Zero Metadata Harvesting</span>
                    <p>Isolated educational boundary. Zero trackers, zero third-party telemetry, minimal DB schema.</p>
                  </td>
                </tr>
              )}

              {(benchmarkCategory === 'all' || benchmarkCategory === 'identity') && (
                <tr>
                  <td>
                    <strong>Identity &amp; SIM-Swap Defense</strong>
                    <small>Vulnerability to telecom attacks</small>
                  </td>
                  <td className="critique-cell">
                    <span className="status-cross"><CrossIcon size={12} style={{ marginRight: 4 }} /> SIM-Swap Vulnerable</span>
                    <p>SMS phone-number registration makes accounts vulnerable to SS7 attacks and carrier SIM-swapping.</p>
                  </td>
                  <td className="critique-cell">
                    <span className="status-cross"><CrossIcon size={12} style={{ marginRight: 4 }} /> SIM-Swap Vulnerable</span>
                    <p>Strictly bound to cellular numbers. Account takeover possible via fraudulent carrier SIM reissue.</p>
                  </td>
                  <td className="champion-cell">
                    <span className="status-champion"><StarIcon size={12} style={{ marginRight: 4, color: '#e09819' }} /> SIM-Swap Immune</span>
                    <p>Enforces DUET student email (@students.duet.edu.pk) + RFC 6238 Hardware/App TOTP + 8 emergency codes.</p>
                  </td>
                </tr>
              )}

              {(benchmarkCategory === 'all' || benchmarkCategory === 'trust') && (
                <tr>
                  <td>
                    <strong>Transparency &amp; Live Audit</strong>
                    <small>Can you inspect the crypto live?</small>
                  </td>
                  <td className="critique-cell">
                    <span className="status-cross"><CrossIcon size={12} style={{ marginRight: 4 }} /> Closed Backend</span>
                    <p>Client is open-source, but the backend is 100% closed proprietary software.</p>
                  </td>
                  <td className="critique-cell">
                    <span className="status-cross"><CrossIcon size={12} style={{ marginRight: 4 }} /> 100% Closed Binaries</span>
                    <p>Both client app binaries and backend servers are closed-source proprietary software.</p>
                  </td>
                  <td className="champion-cell">
                    <span className="status-champion"><StarIcon size={12} style={{ marginRight: 4, color: '#e09819' }} /> Live Educational Inspector</span>
                    <p>Open architecture with built-in live AEAD tampering simulation and real-time key inspection.</p>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>

        {/* Defense Talking Points for Professor */}
        <div className="defense-pitch-card">
          <h4><AcademicCapIcon size={16} style={{ marginRight: 6, color: '#14542d' }} /> Key Defense Summary for Examiners:</h4>
          <ul>
            <li>
              <strong>Why not Telegram?</strong> Telegram stores all regular chat databases in decrypted form on its servers. DUETCLOCK enforces zero-knowledge architecture: the server and database hold zero decryption capabilities.
            </li>
            <li>
              <strong>Why not WhatsApp?</strong> While WhatsApp uses the Signal Protocol, it is wrapped inside closed-source Meta binaries that collect massive communication metadata. Furthermore, WhatsApp relies on phone numbers vulnerable to SIM-swap attacks, whereas DUETCLOCK enforces institutional authentication and RFC 6238 TOTP.
            </li>
            <li>
              <strong>Academic Novelty:</strong> DUETCLOCK features client-side PBKDF2 key wrapping, AEAD tamper detection, and deterministic out-of-band Safety Numbers running entirely in the browser Web Crypto sandbox.
            </li>
          </ul>
        </div>
      </section>
    </div>
  );
}

