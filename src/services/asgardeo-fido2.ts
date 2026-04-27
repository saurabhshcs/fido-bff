/**
 * Asgardeo FIDO2 / WebAuthn service wrapper.
 *
 * Wraps the four Asgardeo FIDO2 REST endpoints:
 *   POST /api/users/v2/me/webauthn/start-registration
 *   POST /api/users/v2/me/webauthn/finish-registration
 *   POST /api/users/v2/me/webauthn/start-assertion
 *   POST /api/users/v2/me/webauthn/finish-assertion
 *
 * Mock mode (MOCK_AUTH=true): returns realistic stub data without hitting Asgardeo.
 * All functions throw AppError on non-2xx responses — never plain Error.
 */
import { randomBytes } from 'crypto';
import { config } from '../config';
import { AppError } from '../middleware/errorHandler';

// ─── WebAuthn payload types ───────────────────────────────────────────────────

export interface AttestationResponse {
  id: string;
  rawId: string;
  response: {
    attestationObject: string;
    clientDataJSON: string;
  };
  type: 'public-key';
}

export interface AssertionResponse {
  id: string;
  rawId: string;
  response: {
    authenticatorData: string;
    clientDataJSON: string;
    signature: string;
    userHandle?: string;
  };
  type: 'public-key';
}

export interface RegistrationOptions {
  challenge: string;
  timeout: number;
  rp: { name: string; id: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: Array<{ alg: number; type: string }>;
  attestation: string;
}

export interface RegistrationResult {
  credentialId: string;
  signCount: number;
}

export interface AssertionOptions {
  challenge: string;
  timeout: number;
  rpId: string;
  allowCredentials: unknown[];
  userVerification: string;
}

export interface AssertionResult {
  sub: string;
  email: string;
  displayName: string;
  signCount: number;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Obtain an app-level access token via client_credentials grant.
 * Used for FIDO2 start-assertion so Asgardeo accepts the request
 * even before the user has established a session.
 */
async function getAppToken(): Promise<string> {
  if (!config.asgardeo.clientSecret) {
    throw new AppError(
      'CONFIG_ERROR',
      'ASGARDEO_CLIENT_SECRET is required for FIDO2 assertion',
      500,
    );
  }
  const credentials = Buffer.from(
    `${config.asgardeo.clientId}:${config.asgardeo.clientSecret}`,
  ).toString('base64');

  const res = await fetch(`${config.asgardeo.baseUrl}/oauth2/token`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      Authorization: `Basic ${credentials}`,
    },
    body: new URLSearchParams({
      grant_type: 'client_credentials',
      scope: 'internal_login',
    }).toString(),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => '');
    console.error('[getAppToken] client_credentials grant failed:', res.status, text);
    throw new AppError('TOKEN_FETCH_ERROR', `Failed to obtain app token (HTTP ${res.status})`, 502);
  }

  const data = (await res.json()) as { access_token: string };
  return data.access_token;
}

/** Issue an authenticated request to Asgardeo FIDO2 API. */
async function asgardeoPost<T>(
  path: string,
  body: unknown,
  accessToken?: string,
): Promise<T> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    'Accept': 'application/json',
  };
  if (accessToken) {
    headers['Authorization'] = `Bearer ${accessToken}`;
  }

  const url = `${config.asgardeo.baseUrl}${path}`;
  console.log(`[asgardeoPost] ${path} headers:`, JSON.stringify(headers));
  console.log(`[asgardeoPost] ${path} body:`, JSON.stringify(body));

  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  });

  // Read as text first so we can log the raw body on any failure.
  const rawText = await res.text();
  console.log(`[asgardeoPost] ${path} HTTP ${res.status}, body: ${rawText.slice(0, 500)}`);

  let json: unknown;
  try {
    json = JSON.parse(rawText);
  } catch {
    throw new AppError(
      'FIDO2_PARSE_ERROR',
      `Asgardeo returned non-JSON (HTTP ${res.status}): ${rawText.slice(0, 200)}`,
      502,
    );
  }

  if (!res.ok) {
    throw new AppError('FIDO2_UPSTREAM_ERROR', `Asgardeo FIDO2 error (HTTP ${res.status})`, 502);
  }

  return json as T;
}

// ─── Service functions ────────────────────────────────────────────────────────

/**
 * Begin WebAuthn registration — requests PublicKeyCredentialCreationOptions.
 * Requires a valid user access token (user must already be authenticated via PKCE).
 */
export async function startRegistration(accessToken: string): Promise<RegistrationOptions> {
  if (config.mock.enabled) {
    return {
      challenge: randomBytes(32).toString('base64url'),
      timeout: 60000,
      rp: { name: 'FIDO2 App', id: 'localhost' },
      user: { id: 'mock-user-id', name: 'mock@example.com', displayName: 'Mock User' },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },
        { alg: -257, type: 'public-key' },
      ],
      attestation: 'none',
    };
  }

  return asgardeoPost<RegistrationOptions>(
    '/api/users/v2/me/webauthn/start-registration',
    { appId: config.fido2.appId },
    accessToken,
  );
}

/**
 * Complete WebAuthn registration — submits the authenticator's attestation response.
 * Asgardeo validates the attestation and stores the public key credential.
 */
export async function finishRegistration(
  body: AttestationResponse,
  accessToken: string,
): Promise<RegistrationResult> {
  if (config.mock.enabled) {
    return { credentialId: 'mock-credential-id', signCount: 0 };
  }

  return asgardeoPost<RegistrationResult>(
    '/api/users/v2/me/webauthn/finish-registration',
    body,
    accessToken,
  );
}

/**
 * Begin WebAuthn assertion — requests PublicKeyCredentialRequestOptions.
 * Uses a client_credentials app token so Asgardeo accepts the request
 * before the user has established a session (passwordless login flow).
 * The username is forwarded in the request body so Asgardeo can look up
 * the user's registered credentials.
 */
export async function startAssertion(username?: string): Promise<AssertionOptions> {
  if (config.mock.enabled) {
    return {
      challenge: randomBytes(32).toString('base64url'),
      timeout: 30000,
      rpId: 'localhost',
      allowCredentials: [],
      userVerification: 'preferred',
    };
  }

  const appToken = await getAppToken();
  return asgardeoPost<AssertionOptions>(
    '/api/users/v2/me/webauthn/start-assertion',
    { appId: config.fido2.appId, ...(username ? { username } : {}) },
    appToken,
  );
}

/**
 * Complete WebAuthn assertion — submits the authenticator's signed assertion.
 * Asgardeo verifies the signature and returns the user identity.
 */
export async function finishAssertion(body: AssertionResponse): Promise<AssertionResult> {
  if (config.mock.enabled) {
    return {
      sub: 'mock-sub',
      email: 'mock@example.com',
      displayName: 'Mock User',
      signCount: 1,
    };
  }

  return asgardeoPost<AssertionResult>(
    '/api/users/v2/me/webauthn/finish-assertion',
    body,
  );
}
