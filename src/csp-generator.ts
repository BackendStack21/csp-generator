/**
 * @file secure_csp_generator.ts
 * @description
 *   SecureCSPGenerator: A hardened Content-Security-Policy (CSP) generator
 *   that fetches HTML content, parses resource references, and builds a
 *   strict CSP header. Core features include:
 *     - HTTPS-only scheme enforcement (configurable)
 *     - SSRF protection (rejects private IPv4/IPv6 by default)
 *     - Streamed HTML download with timeout and max-body-size limits
 *     - Inline <script> hashing (SHA-256) and optional nonce/unsafe-inline
 *     - Inline <style> URL extraction and optional unsafe-inline
 *     - Auto-adding of upgrade-insecure-requests & block-all-mixed-content
 *     - Pluggable logging via Console-like interface
 *     - Extensible directive presets and testable, modular helpers
 *
 * @example
 * import { SecureCSPGenerator } from './secure_csp_generator';
 *
 * (async () => {
 *   const generator = new SecureCSPGenerator('https://example.com', {
 *     presets: { 'connect-src': ['https://api.example.com'] },
 *     allowUnsafeInlineStyle: false,
 *     maxBodySize: 1_000_000,     // 1 MB
 *     timeoutMs: 10_000,          // 10 seconds
 *     allowPrivateOrigins: false,
 *   });
 *   const cspHeader = await generator.generate();
 *   console.log('Content-Security-Policy:', cspHeader);
 * })();
 */

import {JSDOM} from 'jsdom'
import {parse as parseContentType} from 'content-type'
import {createHash} from 'crypto'
import {isIP} from 'net'
import dns from 'dns/promises'

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

/**
 * Configuration options for SecureCSPGenerator.
 */
export interface SecureCSPGeneratorOptions {
  /**
   * User-provided source lists to initialize specific directives.
   * Example: { 'connect-src': ['https://api.example.com'] }
   */
  presets?: Partial<Record<DirectiveName, readonly string[]>>

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
  fetchOptions?: RequestInit

  /**
   * Milliseconds before aborting a slow response (default: 8000).
   */
  timeoutMs?: number

  /**
   * A logger implementing error, warn, info, debug (default: console).
   */
  logger?: Pick<Console, 'error' | 'warn' | 'info' | 'debug'>

  /**
   * If true, adds "require-trusted-types-for 'script'" to the CSP.
   */
  requireTrustedTypes?: boolean
}

/**
 * SecureCSPGenerator:
 * Fetches an HTML page, extracts resource origins,
 * and constructs a robust CSP header string.
 */
export class SecureCSPGenerator {
  /** The target URL to analyze. */
  readonly url: URL

  private readonly opts: Required<SecureCSPGeneratorOptions>
  private readonly logger: Pick<Console, 'error' | 'warn' | 'info' | 'debug'>
  private html: string = ''
  private readonly sources = new Map<DirectiveName, Set<string>>()

  private detectedInlineScript = false
  private detectedInlineStyle = false
  private detectedEval = false

  /**
   * @param inputUrl - URL of the page to analyze (must be non-empty)
   * @param opts - Configuration options to control fetching and policy
   * @throws Error on invalid URL or insecure scheme when allowHttp=false
   */
  constructor(inputUrl: string, opts: SecureCSPGeneratorOptions = {}) {
    if (!inputUrl) {
      throw new Error('URL must not be empty')
    }
    this.url = new URL(inputUrl)

    const {
      allowHttp = false,
      allowPrivateOrigins = false,
      allowUnsafeInlineScript = false,
      allowUnsafeInlineStyle = false,
      allowUnsafeEval = false,
      presets = {},
      maxBodySize = 0,
      fetchOptions = {},
      timeoutMs = 8_000,
      logger = console,
      requireTrustedTypes = false,
    } = opts

    // Enforce HTTPS unless overridden
    if (!allowHttp && this.url.protocol !== 'https:') {
      throw new Error(
        'Insecure scheme rejected – pass allowHttp: true to override',
      )
    }

    this.opts = {
      allowHttp,
      allowPrivateOrigins,
      allowUnsafeInlineScript,
      allowUnsafeInlineStyle,
      allowUnsafeEval,
      presets,
      maxBodySize,
      fetchOptions,
      timeoutMs,
      logger,
      requireTrustedTypes,
    }
    this.logger = logger

    // Initialize mandatory directives
    this.sources.set('default-src', new Set(["'self'"]))
    this.sources.set('object-src', new Set(["'none'"]))

    // Merge user presets
    for (const [dir, list] of Object.entries(presets) as [
      DirectiveName,
      readonly string[],
    ][]) {
      this.sources.set(dir, new Set(list))
    }
  }

  /**
   * Downloads HTML via fetch, respecting timeouts and size limits.
   * @throws Error if HTTP status not OK, type mismatch, or size exceeded
   */
  private async fetchHtml(): Promise<void> {
    const {timeoutMs, fetchOptions, maxBodySize} = this.opts
    const ac = new AbortController()
    const timer = setTimeout(() => ac.abort(), timeoutMs)

    const response = await fetch(this.url, {
      ...fetchOptions,
      signal: ac.signal,
      headers: {accept: 'text/html', ...fetchOptions.headers},
    }).finally(() => clearTimeout(timer))

    if (!response.ok) {
      throw new Error(`HTTP ${response.status} ${response.statusText}`)
    }

    // Validate Content-Type header if present
    const cType = response.headers.get('content-type')
    if (cType && !/text\/html/i.test(cType)) {
      this.logger.warn(`Expected HTML but got ${cType}`)
    }

    // Enforce content-length if maxBodySize is set
    const length = +response.headers.get('content-length')!
    if (maxBodySize && length > maxBodySize) {
      throw new Error('Response too large – aborting')
    }

    // Stream response body to string
    const reader = response.body?.getReader()
    if (!reader) throw new Error('Failed to read response body')

    const chunks: Uint8Array[] = []
    let received = 0
    while (true) {
      const {done, value} = await reader.read()
      if (done) break
      if (value) {
        received += value.byteLength
        if (maxBodySize && received > maxBodySize) {
          ac.abort()
          throw new Error('Response exceeded maxBodySize')
        }
        chunks.push(value)
      }
    }
    this.html = Buffer.concat(chunks).toString('utf8')
  }

  /**
   * Resolves a raw URL or token into an origin/token and adds it to the CSP set.
   * @param directive - CSP directive to update (e.g., 'script-src')
   * @param rawSrc - URL, nonce/hash token, or relative path
   */
  private async resolveAndAdd(
    directive: DirectiveName,
    rawSrc: string,
  ): Promise<void> {
    const token = rawSrc.trim()

    // Add non-origin tokens ('nonce-...', 'sha256-...', 'unsafe-inline', etc.)
    if (token.startsWith("'") || token.endsWith("='")) {
      this.ensureSet(directive).add(token)
      return
    }

    let absolute: URL
    try {
      absolute = new URL(token, this.url)
    } catch {
      this.logger.debug(`Invalid URL skipped: ${token}`)
      return
    }

    // Enforce HTTPS
    if (!this.opts.allowHttp && absolute.protocol !== 'https:') return

    // SSRF mitigation: block private IPs/domains unless allowed
    if (!this.opts.allowPrivateOrigins) {
      const host = absolute.hostname
      if (host === 'localhost' || host.endsWith('.local')) return
      if (
        isIP(host)
          ? this.isPrivateIp(host)
          : (await dns.lookup(host, {all: true})).some((r) =>
              this.isPrivateIp(r.address),
            )
      ) {
        return
      }
    }

    this.ensureSet(directive).add(absolute.origin)
  }

  /**
   * Tests if an IPv4/v6 address is private or loopback.
   */
  private isPrivateIp(ip: string): boolean {
    return (
      /^10\./.test(ip) ||
      /^192\.168\./.test(ip) ||
      /^172\.(1[6-9]|2\d|3[0-1])\./.test(ip) ||
      /^127\./.test(ip) ||
      ip === '::1' ||
      ip.startsWith('fe80:')
    )
  }

  /**
   * Ensures the directive has an initialized Set, then returns it.
   */
  private ensureSet(dir: DirectiveName): Set<string> {
    if (!this.sources.has(dir)) {
      this.sources.set(dir, new Set())
    }
    return this.sources.get(dir)!
  }

  /**
   * Parses the downloaded HTML, extracts external resources,
   * inline scripts/styles, and computes hashes or origins.
   */
  private async parse(): Promise<void> {
    const dom = new JSDOM(this.html)
    const doc = dom.window.document

    // External resource attributes
    const selectors: Array<[string, string, DirectiveName]> = [
      ['script[src]', 'src', 'script-src'],
      ['link[rel="stylesheet"][href]', 'href', 'style-src'],
      ['img[src]', 'src', 'img-src'],
      ['audio[src]', 'src', 'media-src'],
      ['video[src]', 'src', 'media-src'],
      ['track[src]', 'src', 'media-src'],
      ['iframe[src]', 'src', 'frame-src'],
    ]

    for (const [sel, attr, dir] of selectors) {
      for (const el of Array.from(doc.querySelectorAll(sel))) {
        const val = (el as HTMLElement).getAttribute(attr as string)
        if (val) await this.resolveAndAdd(dir, val)
      }
    }

    // Inline styles
    for (const el of Array.from(doc.querySelectorAll('[style]'))) {
      this.detectedInlineStyle = true
      await this.extractCssUrls(el.getAttribute('style') || '', 'style-src')
    }
    for (const styleEl of Array.from(doc.querySelectorAll('style'))) {
      this.detectedInlineStyle = true
      await this.extractCssUrls(styleEl.textContent || '', 'style-src')
    }

    // Inline scripts hashing and nonce/integrity reuse
    for (const scr of Array.from(doc.querySelectorAll('script'))) {
      if (scr.hasAttribute('src')) continue
      this.detectedInlineScript = true
      const code = (scr.textContent || '').trim()
      if (!code) continue

      if (scr.hasAttribute('nonce')) {
        await this.resolveAndAdd(
          'script-src',
          `\'nonce-${scr.getAttribute('nonce')}\'`,
        )
      } else if (scr.hasAttribute('integrity')) {
        await this.resolveAndAdd(
          'script-src',
          `\'${scr.getAttribute('integrity')}\'`,
        )
      } else {
        const hash = createHash('sha256').update(code).digest('base64')
        await this.resolveAndAdd('script-src', `\'sha256-${hash}\'`)
      }
    }

    // Heuristic eval detection
    if (
      /\b(?:eval\(|Function\s*\(|set(?:Timeout|Interval)\(['"])\b/.test(
        this.html,
      )
    ) {
      this.detectedEval = true
    }
  }

  private cssUrlRe = /url\(\s*(['"]?)([^\)'"]+)\1\s*\)/gi
  private cssImportRe = /@import\s+(?:url\()?['"]?([^\)'"\s]+)['"]?\)?/gi

  /**
   * Extracts CSS resource URLs from inline CSS text and adds them.
   */
  private async extractCssUrls(css: string, dir: DirectiveName): Promise<void> {
    let match: RegExpExecArray | null
    while ((match = this.cssUrlRe.exec(css))) {
      await this.resolveAndAdd(dir, match[2]!)
    }
    while ((match = this.cssImportRe.exec(css))) {
      await this.resolveAndAdd(dir, match[1]!)
    }
  }

  /**
   * Public entry point: fetches, parses, and constructs the final CSP header.
   * @returns A fully-formed CSP header string.
   */
  public async generate(): Promise<string> {
    await this.fetchHtml()
    await this.parse()

    // Conditionally allow unsafe directives
    if (this.detectedInlineScript && this.opts.allowUnsafeInlineScript) {
      this.ensureSet('script-src').add("'unsafe-inline'")
    }
    if (this.detectedInlineStyle && this.opts.allowUnsafeInlineStyle) {
      this.ensureSet('style-src').add("'unsafe-inline'")
    }
    if (this.opts.allowUnsafeEval) {
      this.ensureSet('script-src').add("'unsafe-eval'")
    } else if (this.detectedEval) {
      this.logger.warn(
        'Detected eval-like patterns; without allowUnsafeEval, some scripts may break.',
      )
    }

    // Add Trusted Types directive if enabled
    if (this.opts.requireTrustedTypes) {
      this.sources.set('require-trusted-types-for', new Set(["'script'"]))
    }

    // Enforce mixed-content safety directives
    for (const dir of [
      'upgrade-insecure-requests',
      'block-all-mixed-content',
    ] as DirectiveName[]) {
      if (!this.sources.has(dir)) {
        this.sources.set(dir, new Set())
      }
    }

    // Ensure default-src fallback exists
    if (
      !this.sources.get('default-src') ||
      !this.sources.get('default-src')!.size
    ) {
      this.sources.set('default-src', new Set(["'none'"]))
    }

    // Build header
    const parts: string[] = []
    for (const [dir, vals] of this.sources) {
      if (!vals.size) {
        parts.push(dir)
      } else {
        parts.push(`${dir} ${Array.from(vals).join(' ')}`)
      }
    }

    return parts.join('; ')
  }
}
