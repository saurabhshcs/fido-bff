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
