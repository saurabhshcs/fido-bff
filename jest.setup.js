// Environment variables must be set before any module is imported.
// This file runs via jest.config.js setupFiles, before test code loads.
process.env.SESSION_SECRET = 'test-secret-for-jest-at-least-32-chars-long';
process.env.MOCK_AUTH = 'true';
process.env.FIDO2_ENABLED = 'true';
process.env.SESSION_DURATION_DAYS = '90';
process.env.NODE_ENV = 'test';
