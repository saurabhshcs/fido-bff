import { RequestHandler } from 'express';
import { config } from '../config';

/**
 * Feature-flag guard for all FIDO2 biometric routes.
 * Returns 403 FIDO2_DISABLED when the FIDO2_ENABLED env var is not set to 'true'.
 * Mount this before any handler that should be behind the flag.
 */
export const fido2Gate: RequestHandler = (req, res, next) => {
  if (!config.fido2.enabled) {
    console.warn(`[fido2Gate] BLOCKED ${req.method} ${req.path} — FIDO2_ENABLED=false`);
    res.status(403).json({
      success: false,
      error: {
        code: 'FIDO2_DISABLED',
        message: 'FIDO2 biometric authentication is not yet available',
        statusCode: 403,
      },
    });
    return;
  }
  next();
};
