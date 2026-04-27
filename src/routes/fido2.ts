/**
 * FIDO2 / WebAuthn biometric authentication routes.
 *
 * All routes are gated behind fido2Gate (FIDO2_ENABLED feature flag).
 * Registration routes additionally require an authenticated session (requireSession).
 * Assertion routes are unauthenticated — they establish a new session via biometrics.
 *
 * Endpoint summary:
 *   GET  /fido2/start-registration  — issue PublicKeyCredentialCreationOptions
 *   POST /fido2/finish-registration — verify attestation, store credential
 *   GET  /fido2/start-assertion     — issue PublicKeyCredentialRequestOptions
 *   POST /fido2/finish-assertion    — verify assertion, create trust-tier-2 session
 */
import { Router } from 'express';
import { config } from '../config';
import { AppError } from '../middleware/errorHandler';
import { requireSession } from '../middleware/requireSession';
import { fido2Gate } from '../middleware/fido2Gate';
import * as fido2Service from '../services/asgardeo-fido2';

/** Session duration in milliseconds for a given trust tier. */
function getSessionDurationMs(trustTier: 1 | 2): number {
  const days = config.fido2.sessionDurationDays; // already clamped 1–90
  return trustTier === 2
    ? Math.min(days, 90) * 86_400_000
    : days * 86_400_000;
}

export function createFido2Router(): Router {
  const router = Router();

  /**
   * GET /fido2/start-registration
   * Requires: authenticated session (trust tier 1 minimum — user logged in via PKCE).
   * Issues a WebAuthn credential creation challenge and stores it in the session.
   */
  router.get('/fido2/start-registration', fido2Gate, requireSession, async (req, res, next) => {
    console.log('[GET /fido2/start-registration] Received');
    try {
      const options = await fido2Service.startRegistration(req.session.tokens!.accessToken);
      console.log('[GET /fido2/start-registration] Asgardeo responded OK, rpId:', (options as {rp?: {id?: string}}).rp?.id);

      req.session.fido2Challenge = options.challenge;
      req.session.fido2ChallengeExpiry = Date.now() + 300_000; // 5 minutes

      await new Promise<void>((resolve, reject) =>
        req.session.save(err => (err ? reject(err) : resolve())),
      );

      res.json({ success: true, data: options });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /fido2/finish-registration
   * Requires: authenticated session + valid unexpired challenge in session.
   * Verifies the attestation response and stores the credential ID.
   */
  router.post('/fido2/finish-registration', fido2Gate, requireSession, async (req, res, next) => {
    console.log('[POST /fido2/finish-registration] Received');
    try {
      if (!req.session.fido2ChallengeExpiry || Date.now() > req.session.fido2ChallengeExpiry) {
        throw new AppError('CHALLENGE_EXPIRED', 'Registration challenge has expired — please restart registration', 400);
      }

      const result = await fido2Service.finishRegistration(
        req.body as fido2Service.AttestationResponse,
        req.session.tokens!.accessToken,
      );

      req.session.fido2CredentialId = result.credentialId;
      req.session.fido2SignCount = 0;
      req.session.trustTier = 2;
      // Clear challenge after use
      req.session.fido2Challenge = undefined;
      req.session.fido2ChallengeExpiry = undefined;

      await new Promise<void>((resolve, reject) =>
        req.session.save(err => (err ? reject(err) : resolve())),
      );

      res.json({ success: true, data: { credentialId: result.credentialId, signCount: 0 } });
    } catch (err) {
      next(err);
    }
  });

  /**
   * GET /fido2/start-assertion
   * No session required — this begins a biometric login flow from scratch.
   * Issues a WebAuthn authentication challenge and stores it in the session.
   */
  router.get('/fido2/start-assertion', fido2Gate, async (req, res, next) => {
    console.log('[GET /fido2/start-assertion] Received, email:', req.query.email);
    try {
      const options = await fido2Service.startAssertion(req.query.email as string | undefined);

      req.session.fido2Challenge = options.challenge;
      req.session.fido2ChallengeExpiry = Date.now() + 300_000; // 5 minutes

      await new Promise<void>((resolve, reject) =>
        req.session.save(err => (err ? reject(err) : resolve())),
      );

      res.json({ success: true, data: options });
    } catch (err) {
      next(err);
    }
  });

  /**
   * POST /fido2/finish-assertion
   * No session required — completes biometric login and creates a new session.
   * Validates signCount strictly (must be greater than stored value) to detect cloning.
   */
  router.post('/fido2/finish-assertion', fido2Gate, async (req, res, next) => {
    console.log('[POST /fido2/finish-assertion] Received');
    try {
      if (!req.session.fido2ChallengeExpiry || Date.now() > req.session.fido2ChallengeExpiry) {
        throw new AppError('CHALLENGE_EXPIRED', 'Assertion challenge has expired — please restart authentication', 400);
      }

      const result = await fido2Service.finishAssertion(
        req.body as fido2Service.AssertionResponse,
      );

      // Sign-counter validation: strictly greater-than prevents replay / cloning
      const storedCount = req.session.fido2SignCount ?? 0;
      if (result.signCount <= storedCount) {
        req.session.destroy(() => {});
        throw new AppError(
          'COUNTER_MISMATCH',
          'Assertion rejected: credential cloning suspected',
          401,
        );
      }

      const sessionDuration = getSessionDurationMs(2);

      // Establish a trust-tier-2 session for the biometric-authenticated user
      req.session.user = {
        sub: result.sub,
        email: result.email,
        displayName: result.displayName,
        crmId: null,
      };
      req.session.trustTier = 2;
      req.session.authMethod = 'fido2';
      req.session.fido2SignCount = result.signCount;
      req.session.fido2Challenge = undefined;
      req.session.fido2ChallengeExpiry = undefined;

      await new Promise<void>((resolve, reject) =>
        req.session.save(err => (err ? reject(err) : resolve())),
      );

      // Set a named session cookie so the mobile app knows the session duration
      res.cookie('asg-session', '1', {
        httpOnly: true,
        secure: true,
        sameSite: 'strict',
        maxAge: sessionDuration,
      });

      res.json({
        success: true,
        data: {
          sub: result.sub,
          email: result.email,
          displayName: result.displayName,
          trustTier: 2,
          sessionDuration,
        },
      });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
