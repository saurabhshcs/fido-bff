/**
 * Asgardeo App-native Authentication service.
 *
 * Drives the three-step headless PKCE flow:
 *   Step 1 — POST /oauth2/authorize (response_mode=direct) → returns flowId
 *   Step 2 — POST /oauth2/authn with credentials         → returns authCode
 *   Step 3 — Token exchange via openid-client            → returns tokens + claims
 *
 * PKCE verifier never leaves this server.
 */
import { Client } from 'openid-client';
import { config } from '../config';
import { AppError } from '../middleware/errorHandler';
import { SessionUser } from '../session';
import { generateVerifier, generateChallenge } from './pkce';

// The authenticatorId for BasicAuthenticator (username + password) in Asgardeo's
// App-native API. This is a fixed base64-encoded value — does not change per tenant.
const BASIC_AUTHENTICATOR_ID = 'QmFzaWNBdXRoZW50aWNhdG9y';

interface Authenticator {
  authenticatorId: string;
  displayName?: string;
}

interface InitiateResult {
  flowId: string;
  verifier: string;
  authenticators: Authenticator[];
}

interface AuthorizeResponse {
  flowId?: string;
  flowStatus?: string;
  nextStep?: {
    stepType: string;
    authenticators?: Authenticator[];
  };
  error?: string;
  errorDescription?: string;
}

interface AuthnResponse {
  flowStatus?: string;
  authData?: { code?: string };
  nextStep?: { authenticators?: Array<{ authenticatorId: string }> };
  error?: string;
}

/**
 * Step 1: Initiate the App-native auth flow.
 * Stores PKCE verifier and state so the caller can persist them in the session.
 */
export async function initiateAuthFlow(email: string): Promise<InitiateResult> {
  const verifier = generateVerifier();
  const challenge = generateChallenge(verifier);

  const params = new URLSearchParams({
    client_id: config.asgardeo.clientId,
    response_type: 'code',
    redirect_uri: config.asgardeo.redirectUri,
    scope: config.asgardeo.scopes,
    code_challenge: challenge,
    code_challenge_method: 'S256',
    response_mode: 'direct',
    login_hint: email,
  });

  console.log('[initiateAuthFlow] POST to', `${config.asgardeo.baseUrl}/oauth2/authorize`);
  console.log('[initiateAuthFlow] Params:', {
    client_id: config.asgardeo.clientId,
    redirect_uri: config.asgardeo.redirectUri,
    scope: config.asgardeo.scopes,
  });

  const res = await fetch(`${config.asgardeo.baseUrl}/oauth2/authorize`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });

  let json: AuthorizeResponse;
  try {
    json = (await res.json()) as AuthorizeResponse;
  } catch (err) {
    console.error('[initiateAuthFlow] Failed to parse response:', err);
    throw new AppError('ASGARDEO_PARSE_ERROR', 'Unexpected response from Asgardeo', 502);
  }

  console.log('[initiateAuthFlow] Response:', { status: res.status, json });

  if (!res.ok || !json.flowId) {
    const errorMsg = json.errorDescription ?? json.error ?? 'Failed to initiate auth flow';
    console.error('[initiateAuthFlow] Error:', errorMsg);
    throw new AppError(
      'ASGARDEO_INITIATE_FAILED',
      errorMsg,
      502,
    );
  }

  const authenticators = json.nextStep?.authenticators ?? [];
  console.log('[initiateAuthFlow] Success, flowId:', json.flowId);
  console.log('[initiateAuthFlow] Available authenticators:', authenticators);

  return { flowId: json.flowId, verifier, authenticators };
}

/**
 * Step 2: Submit email + password to Asgardeo App-native authn endpoint.
 * Returns the authorization code on success.
 */
export async function submitCredentials(
  flowId: string,
  email: string,
  password: string,
  authenticators: Authenticator[],
): Promise<string> {
  // Find the username+password authenticator from the available list.
  // Look for one with 'username' and 'password' in requiredParams, or with idp='LOCAL'
  const basicAuthenticator = authenticators.find(auth => {
    const hasRequiredParams = (auth as Record<string, unknown>).requiredParams &&
      Array.isArray((auth as Record<string, unknown>).requiredParams) &&
      (auth as Record<string, unknown>).requiredParams.includes('username') &&
      (auth as Record<string, unknown>).requiredParams.includes('password');

    const isLocal = (auth as Record<string, unknown>).idp === 'LOCAL';

    return hasRequiredParams || isLocal;
  });

  if (!basicAuthenticator) {
    throw new AppError(
      'NO_PASSWORD_AUTHENTICATOR',
      'No password authenticator available for this application. Available: ' +
        authenticators.map((a: Record<string, unknown>) => a.authenticator).join(', '),
      502,
    );
  }

  console.log('[submitCredentials] Using authenticator:', basicAuthenticator);

  const body = {
    flowId,
    selectedAuthenticator: {
      authenticatorId: basicAuthenticator.authenticatorId,
      params: { username: email, password },
    },
  };

  console.log('[submitCredentials] POST to', `${config.asgardeo.baseUrl}/oauth2/authn`);
  console.log('[submitCredentials] Body:', JSON.stringify(body, null, 2));

  const res = await fetch(`${config.asgardeo.baseUrl}/oauth2/authn`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });

  let json: AuthnResponse;
  try {
    json = (await res.json()) as AuthnResponse;
  } catch {
    throw new AppError('ASGARDEO_PARSE_ERROR', 'Unexpected response from Asgardeo', 502);
  }

  console.log('[submitCredentials] Response:', { status: res.status, json });

  // Distinguish upstream failures (5xx/4xx from Asgardeo) from wrong credentials.
  if (!res.ok) {
    const errorMsg = json.error ?? 'Upstream auth error';
    console.error('[submitCredentials] Error:', errorMsg, 'Status:', res.status);
    throw new AppError('ASGARDEO_AUTHN_FAILED', errorMsg, 502);
  }

  if (json.flowStatus !== 'SUCCESS_COMPLETED') {
    console.warn('[submitCredentials] Flow incomplete:', { flowStatus: json.flowStatus, nextStep: json.nextStep });
    throw new AppError(
      'INVALID_CREDENTIALS',
      'Invalid email or password',
      401,
    );
  }

  const code = json.authData?.code;
  if (!code) {
    throw new AppError('ASGARDEO_NO_CODE', 'Auth code missing from Asgardeo response', 502);
  }

  return code;
}

/**
 * Step 3: Exchange the authorization code for tokens using openid-client.
 * Validates the ID token signature against Asgardeo's JWKS.
 * Returns the session user extracted from ID token claims.
 */
export async function exchangeCodeForSession(
  client: Client,
  code: string,
  verifier: string,
): Promise<SessionUser> {
  const tokenSet = await client.grant({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.asgardeo.redirectUri,
    code_verifier: verifier,
  });

  const claims = tokenSet.claims();

  const givenName = (claims.given_name as string | undefined) ?? '';
  const familyName = (claims.family_name as string | undefined) ?? '';
  const fullName = `${givenName} ${familyName}`.trim();

  return {
    sub: claims.sub,
    email: (claims.email as string | undefined) ?? '',
    displayName: fullName || ((claims.email as string | undefined)?.split('@')[0] ?? 'User'),
    crmId: ((claims as Record<string, unknown>).crmId as string | null) ?? null,
  };
}

/**
 * Convenience wrapper: runs all three steps in sequence.
 * For mock mode (MOCK_AUTH=true), bypasses Asgardeo entirely.
 */
export async function login(
  client: Client,
  email: string,
  password: string,
): Promise<SessionUser> {
  if (config.mock.enabled) {
    console.log('[asgardeo.login] Mock auth enabled, bypassing Asgardeo', { email });
    return {
      sub: 'mock-sub',
      email: email || config.mock.email,
      displayName: config.mock.displayName,
      crmId: config.mock.crmId,
    };
  }

  const { flowId, verifier, authenticators } = await initiateAuthFlow(email);
  const code = await submitCredentials(flowId, email, password, authenticators);
  return exchangeCodeForSession(client, code, verifier);
}

/**
 * Revokes the access token at Asgardeo on logout (best-effort — errors are swallowed).
 */
export async function revokeToken(accessToken: string): Promise<void> {
  const body = new URLSearchParams({
    client_id: config.asgardeo.clientId,
    token: accessToken,
  });
  if (config.asgardeo.clientSecret) {
    body.set('client_secret', config.asgardeo.clientSecret);
  }

  await fetch(`${config.asgardeo.baseUrl}/oauth2/revoke`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: body.toString(),
  }).catch(() => {}); // best-effort
}
