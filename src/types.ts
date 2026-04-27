/**
 * Asgardeo App-Native Authentication API Contract
 * Types for mobile app integration with type safety.
 * Exported so mobile clients can import and use these types.
 */

import { SessionUser } from './session';

/**
 * Generic response wrapper for Asgardeo auth endpoints.
 * Allows clients to distinguish success from error states.
 */
export interface AsgardeoAuthResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    statusCode: number;
  };
}

/**
 * Request body for POST /auth/initiate
 * Begins the Asgardeo App-native PKCE flow.
 */
export interface InitiateRequest {
  email: string;
}

/**
 * Response from POST /auth/initiate
 * Returns the flow context needed for Step 2.
 * FlowId is transient (server validates it in /auth/submit).
 */
export interface InitiateResponse {
  flowId: string;
  authenticators: Array<{
    authenticatorId: string;
    displayName?: string;
  }>;
}

/**
 * Request body for POST /auth/submit
 * Completes credential submission and token exchange.
 * Verifier is validated server-side from session (not sent from client).
 */
export interface SubmitRequest {
  email: string;
  password: string;
}

/**
 * Response from POST /auth/submit
 * User profile on success. JWT is set as HttpOnly cookie (not in response body).
 */
export interface SubmitResponse extends SessionUser {
  // email, displayName, crmId inherited from SessionUser
  // JWT set in Set-Cookie header
}

/**
 * Error response (when success: false)
 */
export interface ErrorResponse {
  code: string;
  message: string;
  statusCode: number;
}

/**
 * Re-export SessionUser for mobile app type safety
 */
export type { SessionUser } from './session';
