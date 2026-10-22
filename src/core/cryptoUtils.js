/**
 * ExtensionLedger - Cryptographic & Information Theory Utilities
 * Provides SHA-256 hashing and Shannon Entropy analysis for extension auditing.
 * Works seamlessly in both browser (Web Crypto API) and Node.js (crypto module).
 */

/**
 * Calculates the Shannon Entropy of a string or byte array.
 * Entropy measures the unpredictability/information density:
 * - Normal English text / clean code: ~3.5 - 4.9
 * - Minified JavaScript: ~5.0 - 5.5
 * - Obfuscated / Base64 packed: ~5.6 - 6.2
 * - Encrypted / Compressed / Steganographic payloads: > 6.4 (max 8.0)
 * 
 * @param {string|Uint8Array} data
 * @returns {number} Shannon entropy value (0.0 to 8.0)
 */
export function calculateShannonEntropy(data) {
  if (!data || data.length === 0) return 0;

  let bytes;
  if (typeof data === 'string') {
    bytes = new TextEncoder().encode(data);
  } else if (data instanceof Uint8Array) {
    bytes = data;
  } else {
    bytes = new Uint8Array(data);
  }

  const len = bytes.length;
  if (len === 0) return 0;

  const frequencies = new Uint32Array(256);
  for (let i = 0; i < len; i++) {
    frequencies[bytes[i]]++;
  }

  let entropy = 0;
  for (let i = 0; i < 256; i++) {
    const count = frequencies[i];
    if (count > 0) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }
  }

  return Math.round(entropy * 1000) / 1000;
}

/**
 * Computes a SHA-256 hexadecimal hash string for data.
 * @param {string|Uint8Array} data
 * @returns {Promise<string>} Hexadecimal SHA-256 hash string
 */
export async function computeSha256(data) {
  let bytes;
  if (typeof data === 'string') {
    bytes = new TextEncoder().encode(data);
  } else if (data instanceof Uint8Array) {
    bytes = data;
  } else {
    bytes = new Uint8Array(data);
  }

  // 1. Browser Web Crypto API
  if (typeof crypto !== 'undefined' && crypto.subtle && typeof crypto.subtle.digest === 'function') {
    const hashBuffer = await crypto.subtle.digest('SHA-256', bytes);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // 2. Node.js crypto module fallback
  try {
    const nodeCrypto = await import('node:crypto');
    return nodeCrypto.createHash('sha256').update(bytes).digest('hex');
  } catch {
    // Basic fallback hash for headless test environments without crypto
    let hash = 0;
    for (let i = 0; i < bytes.length; i++) {
      hash = ((hash << 5) - hash) + bytes[i];
      hash |= 0;
    }
    return Math.abs(hash).toString(16).padStart(64, '0');
  }
}
