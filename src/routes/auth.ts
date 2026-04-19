import { Router } from 'express';
import { Client } from 'openid-client';
import { config } from '../config';
import { requireSession } from '../middleware/requireSession';
import { AppError } from '../middleware/errorHandler';
import type { InitiateRequest, InitiateResponse, SubmitRequest, SubmitResponse, AsgardeoAuthResponse } from '../types';
import * as asgardeo from '../services/asgardeo';

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

/**
 * Creates the auth router, injecting the openid-client instance.
 * Implements the two-step Asgardeo App-native PKCE flow:
 *   Step 1: POST /auth/initiate → begin auth flow
 *   Step 2: POST /auth/submit  → exchange credentials for tokens
 */
export function createAuthRouter(client: Client): Router {
  const router = Router();

  /**
   * POST /auth/initiate
   * Body: { email: string }
   * Response: AsgardeoAuthResponse with { flowId, authenticators }
   *
   * Initiates the Asgardeo App-native PKCE flow and stores state in session.
   * The PKCE verifier is stored server-side (never sent to client).
   */
  router.post('/initiate', async (req, res, next) => {
    try {
      const { email } = req.body as InitiateRequest;

      console.log('[POST /auth/initiate] Received request', { email: email ? obfuscateEmail(email.trim()) : undefined });

      if (!email?.trim()) {
        throw new AppError('VALIDATION_ERROR', 'email is required', 400);
      }

      const trimmedEmail = email.trim();
      console.log('[POST /auth/initiate] Calling asgardeo.initiateAuthFlow()...');
      const { flowId, verifier, authenticators } = await asgardeo.initiateAuthFlow(trimmedEmail);

      // Store auth flow state in session (server-side protection of PKCE verifier)
      console.log('[POST /auth/initiate] Storing flow state in session', { email: obfuscateEmail(trimmedEmail), flowId });
      req.session.authFlow = {
        email: trimmedEmail,
        flowId,
        verifier,
        authenticators,
      };

      await new Promise<void>((resolve, reject) =>
        req.session.save(err => (err ? reject(err) : resolve())),
      );

      const response: AsgardeoAuthResponse<InitiateResponse> = {
        success: true,
        data: {
          flowId,
          authenticators: authenticators.map(auth => ({
            authenticatorId: auth.authenticatorId,
            displayName: auth.displayName,
          })),
        },
      };

      console.log('[POST /auth/initiate] Initiate successful, returning flowId');
      res.json(response);
    } catch (err) {
      console.error('[POST /auth/initiate] Error:', err instanceof Error ? err.message : err);
      next(err);
    }
  });

  /**
   * POST /auth/submit
   * Body: { email: string, password: string }
   * Response: AsgardeoAuthResponse with user profile (email, displayName, crmId)
   *
   * Completes the auth flow by:
   *   1. Validating the email matches the initiated flow
   *   2. Submitting credentials to Asgardeo
   *   3. Exchanging code for tokens via OIDC
   *   4. Storing user and tokens in session
   *   5. Setting ID token as HttpOnly, Secure cookie
   */
  router.post('/submit', async (req, res, next) => {
    try {
      const { email, password } = req.body as SubmitRequest;

      console.log('[POST /auth/submit] Received request', { email: email ? obfuscateEmail(email.trim()) : undefined, passwordLength: password?.length });

      if (!email?.trim() || !password) {
        throw new AppError('VALIDATION_ERROR', 'email and password are required', 400);
      }

      // Validate that the session has an active auth flow
      if (!req.session.authFlow) {
        throw new AppError('FLOW_NOT_INITIATED', 'No active auth flow. Call /auth/initiate first.', 400);
      }

      const trimmedEmail = email.trim();

      // Validate email matches the initiated flow (prevents cross-request tampering)
      if (trimmedEmail !== req.session.authFlow.email) {
        console.warn('[POST /auth/submit] Email mismatch', {
          initiated: obfuscateEmail(req.session.authFlow.email),
          submitted: obfuscateEmail(trimmedEmail),
        });
        throw new AppError('EMAIL_MISMATCH', 'Email does not match initiated flow', 400);
      }

      const { flowId, verifier, authenticators } = req.session.authFlow;

      console.log('[POST /auth/submit] Calling asgardeo.submitCredentials()...');
      const code = await asgardeo.submitCredentials(flowId, trimmedEmail, password, authenticators);

      console.log('[POST /auth/submit] Code received, exchanging for tokens...');
      const { user, idToken, accessToken } = await asgardeo.exchangeCodeForSession(client, code, verifier);

      // Store user and tokens in session for subsequent requests
      console.log('[POST /auth/submit] Token exchange successful, saving session', { email: obfuscateEmail(user.email) });
      req.session.user = user;
      req.session.tokens = {
        accessToken,
        idToken,
        expiresAt: Date.now() + 8 * 60 * 60 * 1000, // 8 hours
      };

      // Clear the auth flow state (no longer needed)
      delete req.session.authFlow;

      await new Promise<void>((resolve, reject) =>
        req.session.save(err => (err ? reject(err) : resolve())),
      );

      // Set ID token as HttpOnly, Secure cookie (in addition to session storage)
      // This allows the mobile app to send it with subsequent requests if needed
      res.cookie('id_token', idToken, {
        httpOnly: true,
        secure: config.nodeEnv === 'production',
        sameSite: config.nodeEnv === 'production' ? ('strict' as const) : ('lax' as const),
        maxAge: 8 * 60 * 60 * 1000, // 8 hours
      });

      const response: AsgardeoAuthResponse<SubmitResponse> = {
        success: true,
        data: {
          sub: user.sub,
          email: user.email,
          displayName: user.displayName,
          crmId: user.crmId,
        },
      };

      console.log('[POST /auth/submit] Submit successful, returning user profile');
      res.json(response);
    } catch (err) {
      console.error('[POST /auth/submit] Error:', err instanceof Error ? err.message : err);
      next(err);
    }
  });

  /**
   * GET /auth/session
   * Returns the current session user if authenticated, or 401.
   * Used by mobile app on boot to restore an existing session.
   */
  router.get('/session', requireSession, (req, res) => {
    const { email, displayName, crmId, sub } = req.session.user!;
    const response: AsgardeoAuthResponse<SubmitResponse> = {
      success: true,
      data: { sub, email, displayName, crmId },
    };
    res.json(response);
  });

  /**
   * POST /auth/login
   * Convenience endpoint combining /initiate and /submit into a single step.
   * Body: { email: string, password: string }
   * Response: user profile with email, displayName, crmId
   *
   * This endpoint is used by the mobile app for simplified login flow.
   */
  router.post('/login', async (req, res, next) => {
    try {
      const { email, password } = req.body as { email?: string; password?: string };

      console.log('[POST /auth/login] Received request', { email: email ? obfuscateEmail(email.trim()) : undefined });

      if (!email?.trim() || !password) {
        throw new AppError('VALIDATION_ERROR', 'email and password are required', 400);
      }

      const trimmedEmail = email.trim();

      try {
        // Step 1: Initiate the auth flow
        console.log('[POST /auth/login] Step 1: Initiating flow...');
        const { flowId, verifier, authenticators } = await asgardeo.initiateAuthFlow(trimmedEmail);

        // Step 2: Submit credentials
        console.log('[POST /auth/login] Step 2: Submitting credentials...');
        const code = await asgardeo.submitCredentials(flowId, trimmedEmail, password, authenticators);

        // Step 3: Exchange code for tokens
        console.log('[POST /auth/login] Step 3: Exchanging code for tokens...');
        const { user, idToken, accessToken } = await asgardeo.exchangeCodeForSession(client, code, verifier);

        // Store in session
        console.log('[POST /auth/login] Storing session');
        req.session.user = user;
        req.session.tokens = {
          accessToken,
          idToken,
          expiresAt: Date.now() + 8 * 60 * 60 * 1000, // 8 hours
        };

        await new Promise<void>((resolve, reject) =>
          req.session.save(err => (err ? reject(err) : resolve())),
        );

        // Set ID token as HttpOnly, Secure cookie
        res.cookie('id_token', idToken, {
          httpOnly: true,
          secure: config.nodeEnv === 'production',
          sameSite: config.nodeEnv === 'production' ? ('strict' as const) : ('lax' as const),
          maxAge: 8 * 60 * 60 * 1000, // 8 hours
        });

        const response: AsgardeoAuthResponse<SubmitResponse> = {
          success: true,
          data: {
            sub: user.sub,
            email: user.email,
            displayName: user.displayName,
            crmId: user.crmId,
          },
        };

        console.log('[POST /auth/login] Login successful');
        res.json(response);
      } catch (err) {
        if (err instanceof AppError && err.code === 'INVALID_CREDENTIALS') {
          throw err;
        }
        throw err;
      }
    } catch (err) {
      console.error('[POST /auth/login] Error:', err instanceof Error ? err.message : err);
      next(err);
    }
  });

  /**
   * POST /auth/logout
   * Revokes the access token (best-effort) and destroys the session.
   */
  router.post('/logout', requireSession, async (req, res, next) => {
    try {
      const accessToken = req.session.tokens?.accessToken;

      if (accessToken) {
        await asgardeo.revokeToken(accessToken);
      }

      await new Promise<void>((resolve, reject) =>
        req.session.destroy(err => (err ? reject(err) : resolve())),
      );

      res.clearCookie('connect.sid');
      res.clearCookie('id_token');
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  });

  return router;
}
