import session from 'express-session';
import { config } from './config';

// Module augmentation — adds typed fields to express-session's SessionData.
// This file must be imported before any session usage so the types are available.
declare module 'express-session' {
  interface SessionData {
    /** Set after successful authentication. Cleared on logout. */
    user: SessionUser | undefined;
    /**
     * Tokens stored server-side; never sent to the mobile app.
     * Populated after successful login and cleared on logout.
     */
    tokens: TokenState | undefined;
    /**
     * Auth flow state during PKCE initiate/submit steps.
     * Stores flowId, verifier, and authenticators between /auth/initiate and /auth/submit.
     * Cleared after successful token exchange.
     */
    authFlow:
      | {
          email: string;
          flowId: string;
          verifier: string;
          authenticators: Array<{ authenticatorId: string; displayName?: string }>;
        }
      | undefined;

    // ─── FIDO2 / Phase 2 fields ───────────────────────────────────────────────
    /** Trust tier: 1 = password-only, 2 = biometric-verified. */
    trustTier?: 1 | 2;
    /** Authentication method used to establish this session. */
    authMethod?: 'pkce' | 'fido2';
    /** WebAuthn sign counter — used to detect credential cloning. */
    fido2SignCount?: number;
    /** Stored credential ID after successful FIDO2 registration. */
    fido2CredentialId?: string;
    /** Base64url-encoded challenge issued during start-registration / start-assertion. */
    fido2Challenge?: string;
    /** Unix timestamp (ms) after which the challenge is considered expired. */
    fido2ChallengeExpiry?: number;
  }
}

export interface SessionUser {
  sub: string;
  email: string;
  displayName: string;
  crmId: string | null;
}

interface TokenState {
  accessToken: string;
  idToken: string;
  expiresAt: number;
}

export const sessionMiddleware = session({
  secret: config.sessionSecret,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    // Secure=true is required in production (HTTPS). Leave false for local HTTP dev.
    secure: config.nodeEnv === 'production',
    // 'none' requires Secure=true (RFC 6265bis) — browsers and OkHttp silently drop
    // SameSite=None; Secure=false cookies. Use 'lax' for PoC (works over HTTP).
    sameSite: config.nodeEnv === 'production' ? ('strict' as const) : ('lax' as const),
    maxAge: 8 * 60 * 60 * 1000, // 8 hours
  },
  // Phase 2: replace store with new RedisStore(redisClient)
});
