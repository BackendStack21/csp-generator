/**
 * @file constants.ts
 * @description Shared constants for the CSP generator
 */

/**
 * List of valid CSP directives
 * @see https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy
 */
export const VALID_CSP_DIRECTIVES = [
  'default-src',
  'script-src',
  'style-src',
  'img-src',
  'font-src',
  'connect-src',
  'frame-src',
  'object-src',
  'base-uri',
  'form-action',
  'frame-ancestors',
  'media-src',
  'worker-src',
  'manifest-src',
  'report-uri',
  'report-to',
  'upgrade-insecure-requests',
  'block-all-mixed-content',
  'require-trusted-types-for',
] as const

export type CSPDirective = typeof VALID_CSP_DIRECTIVES[number] 