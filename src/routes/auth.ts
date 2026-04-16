import { Router } from 'express';
import { Client } from 'openid-client';
import { requireSession } from '../middleware/requireSession';
import { AppError } from '../middleware/errorHandler';
import * as asgardeo from '../services/asgardeo';

/**
 * Creates the auth router, injecting the openid-client instance.
 * Client is created once at startup (after OIDC discovery) and shared here.
 */
export function createAuthRouter(client: Client): Router {
  const router = Router();

  /**
   * POST /auth/login
   * Body: { email: string, password: string }
   * Response: { email, displayName, crmId }  +  Set-Cookie: sessionId (httpOnly)
   */
  router.post('/login', async (req, res, next) => {
    try {
      const { email, password } = req.body as { email?: string; password?: string };

      console.log('[POST /auth/login] Received request', { email: email?.trim(), passwordLength: password?.length });

      if (!email?.trim() || !password) {
        throw new AppError('VALIDATION_ERROR', 'email and password are required', 400);
      }

      console.log('[POST /auth/login] Calling asgardeo.login()...');
      const user = await asgardeo.login(client, email.trim(), password);

      console.log('[POST /auth/login] Login successful, saving session', { email: user.email });
      req.session.user = user;
      await new Promise<void>((resolve, reject) =>
        req.session.save(err => (err ? reject(err) : resolve())),
      );

      console.log('[POST /auth/login] Session saved, returning user profile');
      res.json({
        email: user.email,
        displayName: user.displayName,
        crmId: user.crmId,
      });
    } catch (err) {
      console.error('[POST /auth/login] Error:', err instanceof Error ? err.message : err);
      next(err);
    }
  });

  /**
   * GET /auth/session
   * Returns the current session user if authenticated, or 401.
   * Used by SplashScreen on app boot to restore an existing session.
   */
  router.get('/session', requireSession, (req, res) => {
    const { email, displayName, crmId } = req.session.user!;
    res.json({ email, displayName, crmId });
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
      res.status(204).send();
    } catch (err) {
      next(err);
    }
  });

  return router;
}
