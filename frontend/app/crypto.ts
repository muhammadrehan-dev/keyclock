/**
 * Client-Side End-to-End Encryption (E2EE) Module for Keyclock.
 * Uses Web Crypto API (SubtleCrypto) with RSA-OAEP + AES-256-GCM envelope encryption,
 * and PBKDF2 key derivation for zero-knowledge password-encrypted private key storage.
 */

function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

async function deriveWrappingKey(password: string, salt: Uint8Array, iterations: number = 600000): Promise<CryptoKey> {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: salt as unknown as BufferSource,
      iterations,
      hash: 'SHA-256',
    },
    baseKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

export async function generateE2EEKeyPair(): Promise<CryptoKeyPair> {
  return crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256',
    },
    true,
    ['encrypt', 'decrypt']
  );
}

export async function exportPublicKey(publicKey: CryptoKey): Promise<string> {
  const jwk = await crypto.subtle.exportKey('jwk', publicKey);
  return JSON.stringify(jwk);
}

export async function importPublicKey(jwkString: string): Promise<CryptoKey> {
  const jwk = JSON.parse(jwkString);
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['encrypt']
  );
}

function isJsonWebKey(key: CryptoKey | JsonWebKey): key is JsonWebKey {
  return typeof (key as JsonWebKey).kty === 'string';
}

export async function encryptPrivateKeyWithPassword(
  privateKey: CryptoKey | JsonWebKey,
  password: string,
  iterations: number = 600000
): Promise<string> {
  const jwk = isJsonWebKey(privateKey) ? privateKey : await crypto.subtle.exportKey('jwk', privateKey);
  const jwkBytes = new TextEncoder().encode(JSON.stringify(jwk));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await deriveWrappingKey(password, salt, iterations);
  const encryptedBytes = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    jwkBytes
  );
  return JSON.stringify({
    v: 2,
    iter: iterations,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(new Uint8Array(encryptedBytes)),
  });
}

export interface DecryptedPrivateKey {
  privateKey: CryptoKey;
  needsRewrap: boolean;
  jwk: JsonWebKey;
}

export async function decryptPrivateKeyWithPassword(
  encryptedBundleStr: string,
  password: string
): Promise<DecryptedPrivateKey> {
  let bundle;
  try {
    bundle = JSON.parse(encryptedBundleStr);
  } catch {
    throw new Error('Invalid key bundle format.');
  }
  const salt = base64ToBytes(bundle.salt);
  const iv = base64ToBytes(bundle.iv);
  const ct = base64ToBytes(bundle.ct);
  const iterations = bundle.iter || (bundle.v === 1 ? 100000 : 600000);
  const wrappingKey = await deriveWrappingKey(password, salt, iterations);
  let decryptedBytes: ArrayBuffer;
  try {
    decryptedBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource },
      wrappingKey,
      ct as unknown as BufferSource
    );
  } catch {
    throw new Error('Could not decrypt private key with your account password. If you recently reset your password via email, your old key cannot be unlocked with the new password.');
  }
  const jwkStr = new TextDecoder().decode(decryptedBytes);
  const jwk: JsonWebKey = JSON.parse(jwkStr);
  // Import as non-extractable in memory for enhanced security
  const privateKey = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    false,
    ['decrypt']
  );
  const needsRewrap = bundle.v < 2 || !bundle.iter || bundle.iter < 600000;
  return { privateKey, needsRewrap, jwk };
}

export async function encryptE2EEMessage(
  plaintext: string,
  recipientPublicKey: CryptoKey,
  senderPublicKey: CryptoKey
): Promise<{ recipientCiphertext: string; senderCiphertext: string }> {
  // 1. Generate ephemeral 256-bit AES-GCM symmetric key
  const aesKey = await crypto.subtle.generateKey(
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt']
  );
  const rawAesKey = await crypto.subtle.exportKey('raw', aesKey);

  // 2. Encrypt plaintext message with AES-GCM
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plaintextBytes = new TextEncoder().encode(plaintext);
  const encryptedMsgBytes = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    aesKey,
    plaintextBytes
  );
  const msgCiphertextBase64 = bytesToBase64(new Uint8Array(encryptedMsgBytes));
  const ivBase64 = bytesToBase64(iv);

  // 3. Encrypt the AES key for recipient using recipient's RSA-OAEP public key
  const encKeyRecipientBytes = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    recipientPublicKey,
    rawAesKey
  );

  // 4. Encrypt the AES key for sender using sender's RSA-OAEP public key (for Sent mailbox)
  const encKeySenderBytes = await crypto.subtle.encrypt(
    { name: 'RSA-OAEP' },
    senderPublicKey,
    rawAesKey
  );

  const recipientEnvelope = 'E2EE:' + bytesToBase64(new TextEncoder().encode(JSON.stringify({
    v: 1,
    iv: ivBase64,
    key: bytesToBase64(new Uint8Array(encKeyRecipientBytes)),
    ct: msgCiphertextBase64,
  })));

  const senderEnvelope = 'E2EE:' + bytesToBase64(new TextEncoder().encode(JSON.stringify({
    v: 1,
    iv: ivBase64,
    key: bytesToBase64(new Uint8Array(encKeySenderBytes)),
    ct: msgCiphertextBase64,
  })));

  return { recipientCiphertext: recipientEnvelope, senderCiphertext: senderEnvelope };
}

export async function decryptE2EEMessage(
  ciphertextPayload: string,
  userPrivateKey: CryptoKey | null
): Promise<{ text: string; isEncrypted: boolean; error?: boolean }> {
  if (!ciphertextPayload.startsWith('E2EE:')) {
    // Legacy plaintext message
    return { text: ciphertextPayload, isEncrypted: false };
  }

  if (!userPrivateKey) {
    return { text: '[Encrypted message - enter password to unlock]', isEncrypted: true, error: true };
  }

  try {
    const jsonStr = new TextDecoder().decode(base64ToBytes(ciphertextPayload.slice(5)));
    const envelope = JSON.parse(jsonStr);
    const encKeyBytes = base64ToBytes(envelope.key);
    const rawAesKey = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      userPrivateKey,
      encKeyBytes as unknown as BufferSource
    );
    const aesKey = await crypto.subtle.importKey(
      'raw',
      rawAesKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
    const iv = base64ToBytes(envelope.iv);
    const ct = base64ToBytes(envelope.ct);
    const decryptedBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource },
      aesKey,
      ct as unknown as BufferSource
    );
    return { text: new TextDecoder().decode(decryptedBytes), isEncrypted: true };
  } catch (err) {
    console.error('E2EE decryption error:', err);
    return { text: '[Encrypted message - could not decrypt]', isEncrypted: true, error: true };
  }
}

const SESSION_KEY = 'keyclock_e2ee_private_key_jwk';

export async function savePrivateKeyToSession(keyOrJwk: CryptoKey | JsonWebKey): Promise<void> {
  if (typeof window === 'undefined') return;
  try {
    if (isJsonWebKey(keyOrJwk)) {
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(keyOrJwk));
    } else if (keyOrJwk.extractable) {
      const jwk = await crypto.subtle.exportKey('jwk', keyOrJwk);
      sessionStorage.setItem(SESSION_KEY, JSON.stringify(jwk));
    }
  } catch {
    // If not extractable or storage full, ignore
  }
}

export async function loadPrivateKeyFromSession(): Promise<CryptoKey | null> {
  if (typeof window === 'undefined') return null;
  const saved = sessionStorage.getItem(SESSION_KEY);
  if (!saved) return null;
  try {
    const jwk = JSON.parse(saved);
    // Keep private key non-extractable in memory
    return await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      false,
      ['decrypt']
    );
  } catch {
    return null;
  }
}

export function clearPrivateKeyFromSession(): void {
  if (typeof window === 'undefined') return;
  sessionStorage.removeItem(SESSION_KEY);
}

// Clear sensitive keys from sessionStorage on tab close / pagehide
if (typeof window !== 'undefined') {
  window.addEventListener('pagehide', () => {
    clearPrivateKeyFromSession();
  });
}

export async function exportPrivateKeyToJwk(privateKey: CryptoKey): Promise<JsonWebKey | null> {
  if (!privateKey.extractable) return null;
  try {
    return await crypto.subtle.exportKey('jwk', privateKey);
  } catch {
    return null;
  }
}

export function parseEnvelope(ciphertextPayload: string): { v: number; iv: string; key: string; ct: string; rawJson: string } | null {
  if (!ciphertextPayload || !ciphertextPayload.startsWith('E2EE:')) return null;
  try {
    const rawJson = new TextDecoder().decode(base64ToBytes(ciphertextPayload.slice(5)));
    const envelope = JSON.parse(rawJson);
    return {
      v: envelope.v ?? 1,
      iv: envelope.iv || '',
      key: envelope.key || '',
      ct: envelope.ct || '',
      rawJson,
    };
  } catch {
    return null;
  }
}

export function tamperEnvelope(ciphertextPayload: string): string {
  if (!ciphertextPayload || !ciphertextPayload.startsWith('E2EE:')) return ciphertextPayload;
  try {
    const rawJson = new TextDecoder().decode(base64ToBytes(ciphertextPayload.slice(5)));
    const envelope = JSON.parse(rawJson);
    if (envelope.ct && envelope.ct.length > 4) {
      // Flip the last two characters of the ciphertext/tag
      const originalCt = envelope.ct;
      const flipped = originalCt.slice(0, -2) + (originalCt.slice(-2) === 'AA' ? 'BB' : 'AA');
      envelope.ct = flipped;
    } else {
      envelope.ct = 'TAMPERED_TAG_BYTES';
    }
    return 'E2EE:' + bytesToBase64(new TextEncoder().encode(JSON.stringify(envelope)));
  } catch {
    return ciphertextPayload + '_TAMPERED';
  }
}

export async function diagnoseDecryption(
  ciphertextPayload: string,
  userPrivateKey: CryptoKey | null
): Promise<{
  isE2EE: boolean;
  envelope: { v: number; iv: string; key: string; ct: string } | null;
  aesKeyUnwrapped: boolean;
  decryptedPlaintext: string | null;
  integrityError: boolean;
  errorMessage: string | null;
}> {
  if (!ciphertextPayload || !ciphertextPayload.startsWith('E2EE:')) {
    return {
      isE2EE: false,
      envelope: null,
      aesKeyUnwrapped: false,
      decryptedPlaintext: ciphertextPayload,
      integrityError: false,
      errorMessage: null,
    };
  }

  const envelope = parseEnvelope(ciphertextPayload);
  if (!envelope) {
    return {
      isE2EE: true,
      envelope: null,
      aesKeyUnwrapped: false,
      decryptedPlaintext: null,
      integrityError: true,
      errorMessage: 'Envelope JSON structure corrupted or invalid base64.',
    };
  }

  if (!userPrivateKey) {
    return {
      isE2EE: true,
      envelope,
      aesKeyUnwrapped: false,
      decryptedPlaintext: null,
      integrityError: false,
      errorMessage: 'Private key is locked. Enter master password to decrypt.',
    };
  }

  let aesKey: CryptoKey;
  try {
    const encKeyBytes = base64ToBytes(envelope.key);
    const rawAesKey = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      userPrivateKey,
      encKeyBytes as unknown as BufferSource
    );
    aesKey = await crypto.subtle.importKey(
      'raw',
      rawAesKey,
      { name: 'AES-GCM' },
      false,
      ['decrypt']
    );
  } catch (err) {
    return {
      isE2EE: true,
      envelope,
      aesKeyUnwrapped: false,
      decryptedPlaintext: null,
      integrityError: false,
      errorMessage: `RSA-OAEP Key Unwrapping Failed: This message was not encrypted for your public key (${err instanceof Error ? err.message : String(err)}).`,
    };
  }

  try {
    const iv = base64ToBytes(envelope.iv);
    const ct = base64ToBytes(envelope.ct);
    const decryptedBytes = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: iv as unknown as BufferSource },
      aesKey,
      ct as unknown as BufferSource
    );
    const plaintext = new TextDecoder().decode(decryptedBytes);
    return {
      isE2EE: true,
      envelope,
      aesKeyUnwrapped: true,
      decryptedPlaintext: plaintext,
      integrityError: false,
      errorMessage: null,
    };
  } catch (err) {
    return {
      isE2EE: true,
      envelope,
      aesKeyUnwrapped: true,
      decryptedPlaintext: null,
      integrityError: true,
      errorMessage: `AEAD Integrity Tag Mismatch! Ciphertext or IV was modified (${err instanceof Error ? err.message : String(err)}).`,
    };
  }
}

/**
 * Computes a standardized SHA-256 fingerprint for a single public key.
 * Formatted as 8 groups of 4 uppercase hex characters (e.g., A8B1-4C92-...).
 */
export async function computeKeyFingerprint(pubKeyJwkString: string): Promise<string> {
  try {
    const parsed = typeof pubKeyJwkString === 'string' ? JSON.parse(pubKeyJwkString) : pubKeyJwkString;
    const canonical = JSON.stringify({ kty: parsed.kty, n: parsed.n, e: parsed.e });
    const buffer = new TextEncoder().encode(canonical);
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    return hex.match(/.{1,4}/g)?.slice(0, 8).join('-') || hex.slice(0, 32);
  } catch {
    return 'INVALID_KEY_FORMAT';
  }
}

/**
 * Computes a 60-digit Cryptographic Safety Number (Anti-MITM Verification Code)
 * shared between two students, formatted as 12 groups of 5 digits (Signal/WhatsApp standard).
 * Uses deterministic lexicographical sorting of both public keys so both users compute
 * the exact same 60-digit sequence independently.
 */
export async function computeSafetyNumber(userPubKeyJwk: string, peerPubKeyJwk: string): Promise<string> {
  try {
    const keyA = typeof userPubKeyJwk === 'string' ? userPubKeyJwk.trim() : JSON.stringify(userPubKeyJwk);
    const keyB = typeof peerPubKeyJwk === 'string' ? peerPubKeyJwk.trim() : JSON.stringify(peerPubKeyJwk);
    const sorted = [keyA, keyB].sort().join('::DUET_SAFETY_SALT::');
    
    const encoder = new TextEncoder();
    let currentHash = await crypto.subtle.digest('SHA-256', encoder.encode(sorted));
    const fullBytes: number[] = [];
    
    for (let round = 0; round < 3; round++) {
      fullBytes.push(...Array.from(new Uint8Array(currentHash)));
      currentHash = await crypto.subtle.digest('SHA-256', new Uint8Array(currentHash));
    }
    
    const blocks: string[] = [];
    for (let i = 0; i < 12; i++) {
      const offset = i * 4;
      const num = ((fullBytes[offset] << 24) | (fullBytes[offset + 1] << 16) | (fullBytes[offset + 2] << 8) | fullBytes[offset + 3]) >>> 0;
      const fiveDigits = (num % 100000).toString().padStart(5, '0');
      blocks.push(fiveDigits);
    }
    
    return blocks.join(' ');
  } catch {
    return 'Could not compute safety number. Ensure both users have valid public keys.';
  }
}
