import 'dotenv/config';

function requireEnv(key: string): string {
  const val = process.env[key];
  if (!val) throw new Error(`Missing required environment variable: ${key}`);
  return val;
}

const mockEnabled = process.env.MOCK_AUTH === 'true';

// When MOCK_AUTH=true the Asgardeo env vars are not used, so we don't require them.
const asgardeoEnv = (key: string): string =>
  mockEnabled ? '' : requireEnv(key);

export const config = {
  nodeEnv: process.env.NODE_ENV ?? 'development',
  port: parseInt(process.env.PORT ?? '3001', 10),
  sessionSecret: requireEnv('SESSION_SECRET'),
  asgardeo: {
    baseUrl: asgardeoEnv('ASGARDEO_BASE_URL'),
    clientId: asgardeoEnv('ASGARDEO_CLIENT_ID'),
    clientSecret: process.env.ASGARDEO_CLIENT_SECRET,
    redirectUri: asgardeoEnv('ASGARDEO_REDIRECT_URI'),
    scopes: 'openid profile email internal_login',
  },
  corsOrigin: process.env.CORS_ORIGIN ?? 'http://localhost:8081',
  mock: {
    enabled: process.env.MOCK_AUTH === 'true',
    email: process.env.MOCK_EMAIL ?? 'demo@example.com',
    displayName: process.env.MOCK_DISPLAY_NAME ?? 'Demo User',
    crmId: process.env.MOCK_CRM_ID ?? 'CRM-mock-001',
  },
  fido2: {
    /** Feature flag — set FIDO2_ENABLED=true to activate FIDO2 biometric routes. */
    enabled: process.env.FIDO2_ENABLED === 'true',
    /** Session duration in days, clamped to [1, 90]. Defaults to 15. */
    sessionDurationDays: Math.max(1, Math.min(
      parseInt(process.env.SESSION_DURATION_DAYS || '15', 10),
      90,
    )),
    /**
     * The RP origin (appId) sent to Asgardeo's FIDO2 API.
     * Must match the trusted origin registered in the Asgardeo console.
     * Defaults to the origin of the redirect URI (e.g. http://localhost:3001).
     */
    appId: process.env.FIDO2_APP_ID ??
      new URL(mockEnabled ? 'http://localhost:3001/auth/callback' : (process.env.ASGARDEO_REDIRECT_URI ?? 'http://localhost:3001/auth/callback')).origin,
  },
} as const;
