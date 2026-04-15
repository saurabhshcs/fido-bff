import { randomBytes, createHash } from 'crypto';

/**
 * Generates a PKCE code_verifier (43–128 random base64url characters, per RFC 7636).
 */
export function generateVerifier(): string {
  // 48 bytes → 64 base64url chars. RFC 7636 requires 43–128 chars.
  // Using 32 bytes (43 chars) sits at the minimum boundary where some IdP
  // implementations have off-by-one validation bugs; 48 is safely in range.
  return randomBytes(48).toString('base64url');
}

/**
 * Derives the code_challenge from a verifier using S256 method.
 * S256: BASE64URL(SHA256(ASCII(code_verifier)))
 */
export function generateChallenge(verifier: string): string {
  return createHash('sha256').update(verifier).digest('base64url');
}

/**
 * Generates a random state value for CSRF protection.
 */
export function generateState(): string {
  return randomBytes(16).toString('hex');
}
