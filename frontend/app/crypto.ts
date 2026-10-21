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

async function deriveWrappingKey(password: string, salt: Uint8Array): Promise<CryptoKey> {
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
      iterations: 100000,
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

export async function encryptPrivateKeyWithPassword(privateKey: CryptoKey, password: string): Promise<string> {
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  const jwkBytes = new TextEncoder().encode(JSON.stringify(jwk));
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const wrappingKey = await deriveWrappingKey(password, salt);
  const encryptedBytes = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    wrappingKey,
    jwkBytes
  );
  return JSON.stringify({
    v: 1,
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ct: bytesToBase64(new Uint8Array(encryptedBytes)),
  });
}

export async function decryptPrivateKeyWithPassword(encryptedBundleStr: string, password: string): Promise<CryptoKey> {
  const bundle = JSON.parse(encryptedBundleStr);
  const salt = base64ToBytes(bundle.salt);
  const iv = base64ToBytes(bundle.iv);
  const ct = base64ToBytes(bundle.ct);
  const wrappingKey = await deriveWrappingKey(password, salt);
  const decryptedBytes = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: iv as unknown as BufferSource },
    wrappingKey,
    ct as unknown as BufferSource
  );
  const jwkStr = new TextDecoder().decode(decryptedBytes);
  const jwk = JSON.parse(jwkStr);
  return crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-OAEP', hash: 'SHA-256' },
    true,
    ['decrypt']
  );
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

export async function savePrivateKeyToSession(privateKey: CryptoKey): Promise<void> {
  if (typeof window === 'undefined') return;
  const jwk = await crypto.subtle.exportKey('jwk', privateKey);
  sessionStorage.setItem(SESSION_KEY, JSON.stringify(jwk));
}

export async function loadPrivateKeyFromSession(): Promise<CryptoKey | null> {
  if (typeof window === 'undefined') return null;
  const saved = sessionStorage.getItem(SESSION_KEY);
  if (!saved) return null;
  try {
    const jwk = JSON.parse(saved);
    return await crypto.subtle.importKey(
      'jwk',
      jwk,
      { name: 'RSA-OAEP', hash: 'SHA-256' },
      true,
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
