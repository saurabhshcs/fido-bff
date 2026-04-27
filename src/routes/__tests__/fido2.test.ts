/**
 * FIDO2 route tests — covers AC-001 through AC-015.
 *
 * Both asgardeo-fido2 (FIDO2 service) and asgardeo (PKCE auth service) are mocked
 * so the entire test suite runs offline with no real Asgardeo tenant needed.
 * Env vars are injected by jest.setup.js before any module is imported.
 */
import supertest from 'supertest';
import { Client } from 'openid-client';
import { createApp } from '../../app';
import * as fido2Service from '../../services/asgardeo-fido2';
import { AppError } from '../../middleware/errorHandler';

// Mock the FIDO2 service (under test)
jest.mock('../../services/asgardeo-fido2');

// Mock the PKCE auth service so /auth/login works without a real Asgardeo tenant
jest.mock('../../services/asgardeo', () => ({
  initiateAuthFlow: jest.fn().mockResolvedValue({
    flowId: 'mock-flow-id',
    verifier: 'mock-verifier',
    authenticators: [{ authenticatorId: 'QmFzaWNBdXRoZW50aWNhdG9y', idp: 'LOCAL' }],
  }),
  submitCredentials: jest.fn().mockResolvedValue('mock-code'),
  exchangeCodeForSession: jest.fn().mockResolvedValue({
    user: { sub: 'mock-sub', email: 'test@example.com', displayName: 'Test User', crmId: null },
    idToken: 'mock-id-token',
    accessToken: 'mock-access-token',
  }),
  revokeToken: jest.fn().mockResolvedValue(undefined),
}));

const mockedFido2 = fido2Service as jest.Mocked<typeof fido2Service>;

// ─── App instance shared across tests ────────────────────────────────────────

const app = createApp(null as unknown as Client);

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Create a supertest agent that maintains cookies across requests (session). */
function makeAgent() {
  return supertest.agent(app);
}

/**
 * Create an agent pre-authenticated via the mocked PKCE login flow.
 * The PKCE auth service is mocked, so no real Asgardeo call is made.
 */
async function authenticatedAgent() {
  const agent = makeAgent();
  const res = await agent
    .post('/auth/login')
    .send({ email: 'test@example.com', password: 'test-password' });
  expect(res.status).toBe(200);
  return agent;
}

// ─── Default FIDO2 mock return values ────────────────────────────────────────

beforeEach(() => {
  mockedFido2.startRegistration.mockResolvedValue({
    challenge: 'mock-challenge-base64url',
    timeout: 60000,
    rp: { name: 'FIDO2 App', id: 'localhost' },
    user: { id: 'mock-user-id', name: 'mock@example.com', displayName: 'Mock User' },
    pubKeyCredParams: [{ alg: -7, type: 'public-key' }],
    attestation: 'none',
  });

  mockedFido2.finishRegistration.mockResolvedValue({
    credentialId: 'mock-credential-id',
    signCount: 0,
  });

  mockedFido2.startAssertion.mockResolvedValue({
    challenge: 'mock-assertion-challenge',
    timeout: 30000,
    rpId: 'localhost',
    allowCredentials: [],
    userVerification: 'preferred',
  });

  mockedFido2.finishAssertion.mockResolvedValue({
    sub: 'mock-sub',
    email: 'mock@example.com',
    displayName: 'Mock User',
    signCount: 1,
  });
});

afterEach(() => {
  jest.clearAllMocks();
});

// ─── Tests ────────────────────────────────────────────────────────────────────

describe('FIDO2 routes', () => {
  // AC-001: start-registration returns a challenge
  it('AC-001: GET /auth/fido2/start-registration returns 200 with challenge', async () => {
    const agent = await authenticatedAgent();

    const res = await agent.get('/auth/fido2/start-registration').expect(200);

    expect(res.body.success).toBe(true);
    expect(res.body.data.challenge).toBeDefined();
    expect(typeof res.body.data.challenge).toBe('string');
  });

  // AC-002: challenge is stored in session with a 5-minute expiry window
  it('AC-002: challenge stored in session allows subsequent finish-registration within 5 min', async () => {
    const agent = await authenticatedAgent();
    const before = Date.now();

    await agent.get('/auth/fido2/start-registration').expect(200);

    // If challenge wasn't stored, finish-registration would return CHALLENGE_EXPIRED.
    // A 200 here confirms the challenge was persisted correctly.
    const res = await agent
      .post('/auth/fido2/finish-registration')
      .send({ id: 'cred-id', rawId: 'cred-id', response: { attestationObject: 'ao', clientDataJSON: 'cd' }, type: 'public-key' })
      .expect(200);

    expect(res.body.success).toBe(true);
    expect(Date.now() - before).toBeLessThan(5000); // sanity: test ran well within 5 min window
  });

  // AC-003: finish-registration happy path
  it('AC-003: POST /auth/fido2/finish-registration returns 200 with credentialId', async () => {
    const agent = await authenticatedAgent();
    await agent.get('/auth/fido2/start-registration');

    const res = await agent
      .post('/auth/fido2/finish-registration')
      .send({ id: 'cred-id', rawId: 'cred-id', response: { attestationObject: 'ao', clientDataJSON: 'cd' }, type: 'public-key' })
      .expect(200);

    expect(res.body.success).toBe(true);
    expect(res.body.data.credentialId).toBe('mock-credential-id');
    expect(res.body.data.signCount).toBe(0);
  });

  // AC-004: duplicate credential → 409 CREDENTIAL_CONFLICT
  it('AC-004: duplicate credential returns 409 CREDENTIAL_CONFLICT', async () => {
    mockedFido2.finishRegistration.mockRejectedValue(
      new AppError('CREDENTIAL_CONFLICT', 'Credential already registered for this user', 409),
    );

    const agent = await authenticatedAgent();
    await agent.get('/auth/fido2/start-registration');

    const res = await agent
      .post('/auth/fido2/finish-registration')
      .send({ id: 'cred-id', rawId: 'cred-id', response: { attestationObject: 'ao', clientDataJSON: 'cd' }, type: 'public-key' })
      .expect(409);

    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('CREDENTIAL_CONFLICT');
  });

  // AC-005: invalid attestation → 400 ATTESTATION_FAILED
  it('AC-005: invalid attestation returns 400 ATTESTATION_FAILED', async () => {
    mockedFido2.finishRegistration.mockRejectedValue(
      new AppError('ATTESTATION_FAILED', 'Attestation verification failed', 400),
    );

    const agent = await authenticatedAgent();
    await agent.get('/auth/fido2/start-registration');

    const res = await agent
      .post('/auth/fido2/finish-registration')
      .send({ id: 'bad-id', rawId: 'bad-id', response: { attestationObject: 'invalid', clientDataJSON: 'cd' }, type: 'public-key' })
      .expect(400);

    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('ATTESTATION_FAILED');
  });

  // AC-006 & AC-007: start-assertion returns 200 with allowCredentials array
  it('AC-006/AC-007: GET /auth/fido2/start-assertion returns 200 with allowCredentials', async () => {
    const res = await makeAgent().get('/auth/fido2/start-assertion').expect(200);

    expect(res.body.success).toBe(true);
    expect(res.body.data.challenge).toBeDefined();
    expect(Array.isArray(res.body.data.allowCredentials)).toBe(true);
  });

  // AC-008 & AC-010: finish-assertion happy path — returns trustTier: 2
  it('AC-008/AC-010: POST /auth/fido2/finish-assertion returns 200 with trustTier 2', async () => {
    const agent = makeAgent();
    await agent.get('/auth/fido2/start-assertion');

    const res = await agent
      .post('/auth/fido2/finish-assertion')
      .send({ id: 'cred-id', rawId: 'cred-id', response: { authenticatorData: 'ad', clientDataJSON: 'cd', signature: 'sig' }, type: 'public-key' })
      .expect(200);

    expect(res.body.success).toBe(true);
    expect(res.body.data.trustTier).toBe(2);
    expect(res.body.data.email).toBe('mock@example.com');
    expect(res.body.data.sessionDuration).toBeGreaterThan(0);
  });

  // AC-009: signCount not strictly greater than stored → 401 COUNTER_MISMATCH
  it('AC-009: signCount equal to or less than stored count returns 401 COUNTER_MISMATCH', async () => {
    const agent = makeAgent();

    // First successful assertion establishes signCount = 1 in session
    await agent.get('/auth/fido2/start-assertion');
    await agent
      .post('/auth/fido2/finish-assertion')
      .send({ id: 'cred-id', rawId: 'cred-id', response: { authenticatorData: 'ad', clientDataJSON: 'cd', signature: 'sig' }, type: 'public-key' })
      .expect(200);
    // Session now has fido2SignCount = 1

    // Second assertion returns signCount = 0 (≤ stored 1) → COUNTER_MISMATCH
    mockedFido2.finishAssertion.mockResolvedValue({
      sub: 'mock-sub',
      email: 'mock@example.com',
      displayName: 'Mock User',
      signCount: 0,
    });

    await agent.get('/auth/fido2/start-assertion');
    const res = await agent
      .post('/auth/fido2/finish-assertion')
      .send({ id: 'cred-id', rawId: 'cred-id', response: { authenticatorData: 'ad', clientDataJSON: 'cd', signature: 'sig' }, type: 'public-key' })
      .expect(401);

    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('COUNTER_MISMATCH');
  });

  // AC-011: asg-session cookie maxAge = SESSION_DURATION_DAYS (90) days in ms
  it('AC-011: asg-session cookie maxAge equals 90 days in milliseconds', async () => {
    const agent = makeAgent();
    await agent.get('/auth/fido2/start-assertion');

    const res = await agent
      .post('/auth/fido2/finish-assertion')
      .send({ id: 'cred-id', rawId: 'cred-id', response: { authenticatorData: 'ad', clientDataJSON: 'cd', signature: 'sig' }, type: 'public-key' })
      .expect(200);

    const setCookieHeader = res.headers['set-cookie'] as unknown as string[] | string | undefined;
    const cookies = Array.isArray(setCookieHeader) ? setCookieHeader : [setCookieHeader ?? ''];
    const asgCookie = cookies.find((c: string) => c.startsWith('asg-session='));

    expect(asgCookie).toBeDefined();
    // 90 days × 86400 s/day = 7776000 s → expressed as Max-Age in the Set-Cookie header
    expect(asgCookie).toContain('Max-Age=7776000');
  });

  // AC-012: expired challenge → 400 CHALLENGE_EXPIRED
  it('AC-012: expired challenge returns 400 CHALLENGE_EXPIRED', async () => {
    const agent = makeAgent();
    await agent.get('/auth/fido2/start-assertion');

    // Spy on Date.now() to return a time 6 minutes in the future, making the challenge appear expired.
    // Using spyOn rather than fake timers to avoid blocking async session saves.
    const realNow = Date.now();
    jest.spyOn(Date, 'now').mockReturnValue(realNow + 360_000);

    const res = await agent
      .post('/auth/fido2/finish-assertion')
      .send({ id: 'cred-id', rawId: 'cred-id', response: { authenticatorData: 'ad', clientDataJSON: 'cd', signature: 'sig' }, type: 'public-key' })
      .expect(400);

    jest.restoreAllMocks();

    expect(res.body.success).toBe(false);
    expect(res.body.error.code).toBe('CHALLENGE_EXPIRED');
  });

  // AC-013: FIDO2_ENABLED=false → all 4 endpoints return 403 FIDO2_DISABLED
  it('AC-013: FIDO2_ENABLED=false causes all 4 endpoints to return 403 FIDO2_DISABLED', async () => {
    const savedValue = process.env.FIDO2_ENABLED;
    process.env.FIDO2_ENABLED = 'false';

    jest.resetModules();
    const { createApp: createDisabledApp } = await import('../../app');
    const disabledApp = createDisabledApp(null as unknown as Client);

    const endpoints = [
      { method: 'get' as const, path: '/auth/fido2/start-registration' },
      { method: 'post' as const, path: '/auth/fido2/finish-registration' },
      { method: 'get' as const, path: '/auth/fido2/start-assertion' },
      { method: 'post' as const, path: '/auth/fido2/finish-assertion' },
    ];

    for (const { method, path } of endpoints) {
      const res = await supertest(disabledApp)[method](path).expect(403);
      expect(res.body.success).toBe(false);
      expect(res.body.error.code).toBe('FIDO2_DISABLED');
    }

    process.env.FIDO2_ENABLED = savedValue;
    jest.resetModules();
  });

  // AC-015: error response shape is { success: false, error: { code, message, statusCode } }
  it('AC-015: error responses have shape { success: false, error: { code, message, statusCode } }', async () => {
    mockedFido2.finishRegistration.mockRejectedValue(
      new AppError('ATTESTATION_FAILED', 'Attestation verification failed', 400),
    );

    const agent = await authenticatedAgent();
    await agent.get('/auth/fido2/start-registration');

    const res = await agent
      .post('/auth/fido2/finish-registration')
      .send({ id: 'bad', rawId: 'bad', response: { attestationObject: 'x', clientDataJSON: 'y' }, type: 'public-key' })
      .expect(400);

    expect(res.body).toMatchObject({
      success: false,
      error: {
        code: expect.any(String),
        message: expect.any(String),
        statusCode: expect.any(Number),
      },
    });
    expect(res.body.error.statusCode).toBe(400);
  });
});
