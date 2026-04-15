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
    scopes: 'openid profile email',
  },
  corsOrigin: process.env.CORS_ORIGIN ?? 'http://localhost:8081',
  mock: {
    enabled: process.env.MOCK_AUTH === 'true',
    email: process.env.MOCK_EMAIL ?? 'demo@example.com',
    displayName: process.env.MOCK_DISPLAY_NAME ?? 'Demo User',
    crmId: process.env.MOCK_CRM_ID ?? 'CRM-mock-001',
  },
} as const;
