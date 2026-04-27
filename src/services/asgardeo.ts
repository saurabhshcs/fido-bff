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

/**
 * Obfuscate email for logging (privacy protection).
 * Example: saurabhshcs@yahoo.com → saur***@yah***.com
 */
function obfuscateEmail(email: string): string {
  const [local, domain] = email.split('@');
  if (!local || !domain) return email;

  const localVisible = Math.min(4, Math.max(1, Math.floor(local.length / 2)));
  const domainParts = domain.split('.');
  const domainName = domainParts[0];
  const domainTld = domainParts[domainParts.length - 1];
  const domainVisible = Math.min(3, domainName.length);

  return `${local.substring(0, localVisible)}***@${domainName.substring(0, domainVisible)}***.${domainTld}`;
}

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

interface AuthnMessage {
  type?: string;
  messageId?: string;
  message?: string;
  i18nKey?: string;
  context?: unknown;
}

interface AuthnResponse {
  flowStatus?: string;
  authData?: { code?: string };
  nextStep?: {
    authenticators?: Array<{ authenticatorId: string }>;
    messages?: AuthnMessage[];
  };
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
    const a = auth as unknown as Record<string, unknown>;
    const hasRequiredParams =
      Array.isArray(a['requiredParams']) &&
      (a['requiredParams'] as string[]).includes('username') &&
      (a['requiredParams'] as string[]).includes('password');

    const isLocal = a['idp'] === 'LOCAL';

    return hasRequiredParams || isLocal;
  });

  if (!basicAuthenticator) {
    throw new AppError(
      'NO_PASSWORD_AUTHENTICATOR',
      'No password authenticator available for this application. Available: ' +
        authenticators.map(a => (a as unknown as Record<string, unknown>)['authenticator']).join(', '),
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

  // Use JSON.stringify so nested objects (including messages[]) are fully expanded in logs.
  console.log('[submitCredentials] Response:', JSON.stringify({ status: res.status, json }, null, 2));

  // Distinguish upstream failures (5xx/4xx from Asgardeo) from wrong credentials.
  if (!res.ok) {
    const errorMsg = json.error ?? 'Upstream auth error';
    console.error('[submitCredentials] Error:', errorMsg, 'Status:', res.status);
    throw new AppError('ASGARDEO_AUTHN_FAILED', errorMsg, 502);
  }

  if (json.flowStatus !== 'SUCCESS_COMPLETED') {
    // Extract the human-readable message Asgardeo sent in nextStep.messages[].
    const asgardeoMessages = json.nextStep?.messages ?? [];
    const asgardeoMessage = asgardeoMessages
      .map(m => m.message ?? m.i18nKey ?? m.messageId)
      .filter(Boolean)
      .join('; ');

    console.warn('[submitCredentials] Flow incomplete:', JSON.stringify({
      flowStatus: json.flowStatus,
      messages: asgardeoMessages,
      nextStep: json.nextStep,
    }, null, 2));

    throw new AppError(
      'INVALID_CREDENTIALS',
      asgardeoMessage || 'Invalid email or password',
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
 * Returns the session user extracted from ID token claims AND the token set.
 */
export async function exchangeCodeForSession(
  client: Client,
  code: string,
  verifier: string,
): Promise<{ user: SessionUser; idToken: string; accessToken: string }> {
  const tokenSet = await client.grant({
    grant_type: 'authorization_code',
    code,
    redirect_uri: config.asgardeo.redirectUri,
    code_verifier: verifier,
  });

  const claims = tokenSet.claims();

  const email = (claims.email as string | undefined) ?? '';
  const givenName = (claims.given_name as string | undefined) ?? '';
  const familyName = (claims.family_name as string | undefined) ?? '';
  const crmId = ((claims as Record<string, unknown>).crmId as string | null) ?? null;

  console.log('[exchangeCodeForSession] JWT claims:', {
    given_name: givenName || '(not provided)',
    family_name: familyName || '(not provided)',
    email: email ? obfuscateEmail(email) : '(not provided)',
    crmId: crmId || '(not provided)',
  });

  // Build display name: prefer full name, fall back to email prefix, then generic fallback
  const fullName = `${givenName} ${familyName}`.trim();
  const displayName = fullName || email.split('@')[0] || 'User';

  const user: SessionUser = {
    sub: claims.sub,
    email,
    displayName,
    crmId,
  };

  // Return both user profile and tokens for session storage and HttpOnly cookie
  return {
    user,
    idToken: tokenSet.id_token ?? '',
    accessToken: tokenSet.access_token ?? '',
  };
}

/**
 * Convenience wrapper: runs all three steps in sequence.
 * For mock mode (MOCK_AUTH=true), bypasses Asgardeo entirely.
 * Returns user profile and tokens for session storage.
 */
export async function login(
  client: Client,
  email: string,
  password: string,
): Promise<{ user: SessionUser; idToken: string; accessToken: string }> {
  if (config.mock.enabled) {
    console.log('[asgardeo.login] Mock auth enabled, bypassing Asgardeo', { email });
    const user: SessionUser = {
      sub: 'mock-sub',
      email: email || config.mock.email,
      displayName: config.mock.displayName,
      crmId: config.mock.crmId,
    };
    return {
      user,
      idToken: 'mock-id-token',
      accessToken: 'mock-access-token',
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
