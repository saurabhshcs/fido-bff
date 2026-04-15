import { ErrorRequestHandler } from 'express';

export class AppError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly httpStatus: number,
  ) {
    super(message);
    this.name = 'AppError';
  }
}

export const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
  if (err instanceof AppError) {
    res.status(err.httpStatus).json({ code: err.code, message: err.message });
    return;
  }

  // Upstream / network errors
  const status = (err as { status?: number }).status ?? 500;
  console.error('[BFF error]', err);
  res.status(status).json({
    code: 'INTERNAL_ERROR',
    message: 'An unexpected error occurred',
  });
};
