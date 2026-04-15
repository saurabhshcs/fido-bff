import { RequestHandler } from 'express';

/**
 * Auth guard for protected routes.
 * Returns 401 if the session does not contain an authenticated user.
 */
export const requireSession: RequestHandler = (req, res, next) => {
  if (!req.session.user) {
    res.status(401).json({ code: 'SESSION_EXPIRED', message: 'Not authenticated' });
    return;
  }
  next();
};
