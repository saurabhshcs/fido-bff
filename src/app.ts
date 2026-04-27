import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import { Client } from 'openid-client';
import { config } from './config';
import { sessionMiddleware } from './session';
import { createAuthRouter } from './routes/auth';
import { createFido2Router } from './routes/fido2';
import { errorHandler } from './middleware/errorHandler';

export function createApp(client: Client): express.Application {
  const app = express();

  // Security headers
  app.use(helmet());

  // CORS — allow the RN Metro dev server to send credentials (cookies)
  app.use(
    cors({
      origin: config.corsOrigin,
      credentials: true,
    }),
  );

  // Body parsing
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  // Session (httpOnly cookie)
  app.use(sessionMiddleware);

  // Routes
  app.use('/auth', createAuthRouter(client));
  app.use('/auth', createFido2Router()); // Phase 2: FIDO2 biometric routes

  // Health check
  app.get('/health', (_req, res) => res.json({ ok: true }));

  // Central error handler (must be last)
  app.use(errorHandler);

  return app;
}
