/**
 * @file types.ts
 * @description Shared types for both CLI and browser versions of the CSP generator
 */

/**
 * Supported CSP directive names for configuration and output.
 */
export type DirectiveName =
  | 'default-src'
  | 'script-src'
  | 'style-src'
  | 'img-src'
  | 'font-src'
  | 'connect-src'
  | 'frame-src'
  | 'object-src'
  | 'base-uri'
  | 'form-action'
  | 'frame-ancestors'
  | 'media-src'
  | 'worker-src'
  | 'manifest-src'
  | 'report-uri'
  | 'report-to'
  | 'upgrade-insecure-requests'
  | 'block-all-mixed-content'
  | 'require-trusted-types-for'
  | 'sandbox'

/**
 * Shared logger interface that can be used by both CLI and SecureCSPGenerator.
 */
export interface Logger
  extends Pick<Console, 'error' | 'warn' | 'info' | 'debug'> {}

/**
 * Shared presets type that can be used by both CLI and SecureCSPGenerator.
 */
export type CSPPresets = Partial<Record<DirectiveName, readonly string[]>>

/**
 * Base interface for CSP generator options shared between CLI and core generator.
 */
export interface SecureCSPGeneratorOptions {
  /**
   * The URL to analyze and generate a CSP for.
   */
  url?: string
  /**
   * User-provided source lists to initialize specific directives.
   * Example: { 'connect-src': ['https://api.example.com'] }
   */
  presets?: CSPPresets

  /**
   * Allow HTTP URLs in addition to HTTPS (default: false => HTTPS-only).
   */
  allowHttp?: boolean

  /**
   * Permit private IP / localhost origins (default: false => blocked).
   */
  allowPrivateOrigins?: boolean

  /**
   * If true, adds 'unsafe-inline' to 'script-src' when inline scripts detected
   */
  allowUnsafeInlineScript?: boolean

  /**
   * If true, adds 'unsafe-inline' to 'style-src' when inline styles detected
   */
  allowUnsafeInlineStyle?: boolean

  /**
   * If true, adds 'unsafe-eval' to 'script-src' (overrides hash-based safety)
   */
  allowUnsafeEval?: boolean

  /**
   * Maximum allowed bytes for HTML download. 0 = unlimited (default: 0).
   */
  maxBodySize?: number

  /**
   * Options to forward to fetch (headers, credentials, etc.).
   */
  fetchOptions?: Partial<RequestInit>

  /**
   * Milliseconds before aborting a slow response (default: 8000).
   */
  timeoutMs?: number

  /**
   * A logger implementing error, warn, info, debug (default: console).
   */
  logger?: Logger

  /**
   * If true, adds "require-trusted-types-for 'script'" to the CSP.
   */
  requireTrustedTypes?: boolean

  /**
   * the format of the output
   */
  outputFormat?: 'header' | 'raw' | 'json' | 'csp-only'

  /**
   * If true, adds 'strict-dynamic' to 'script-src'
   */
  useStrictDynamic?: boolean

  /**
   * If true, generates and adds a nonce to 'script-src'
   */
  useNonce?: boolean

  /**
   * If true, generates and adds hashes for inline scripts
   */
  useHashes?: boolean

  /**
   * If true, adds 'upgrade-insecure-requests' directive
   */
  upgradeInsecureRequests?: boolean

  /**
   * If true, adds 'block-all-mixed-content' directive
   */
  blockMixedContent?: boolean

  /**
   * If true, adds 'frame-ancestors none' directive
   */
  restrictFraming?: boolean

  /**
   * If true, adds sandbox directive with common permissions
   */
  useSandbox?: boolean
}
