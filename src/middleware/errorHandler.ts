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

export const errorHandler: ErrorRequestHandler = (err, req, res, _next) => {
  if (err instanceof AppError) {
    console.error(`[BFF error] ${req.method} ${req.path} → ${err.code} (HTTP ${err.httpStatus}): ${err.message}`);
    res.status(err.httpStatus).json({
      success: false,
      error: { code: err.code, message: err.message, statusCode: err.httpStatus },
    });
    return;
  }

  // Upstream / network errors
  const status = (err as { status?: number }).status ?? 500;
  console.error(`[BFF error] ${req.method} ${req.path} → INTERNAL_ERROR (HTTP ${status})`, err);
  res.status(status).json({
    success: false,
    error: { code: 'INTERNAL_ERROR', message: 'An unexpected error occurred', statusCode: status },
  });
};
