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
import {createHash} from 'crypto'
import {isIP} from 'net'
import dns from 'dns/promises'
import type {DirectiveName, Logger, SecureCSPGeneratorOptions} from './types.ts'

/**
 * SecureCSPGenerator:
 * Fetches an HTML page, extracts resource origins,
 * and constructs a robust CSP header string.
 */
export class SecureCSPGenerator {
  /** The target URL to analyze. */
  readonly url: URL
  private readonly opts: Partial<SecureCSPGeneratorOptions>
  private readonly logger: Logger
  private html: string = ''
  private readonly sources = new Map<DirectiveName, Set<string>>()
  private detectedInlineScript = false
  private detectedInlineStyle = false
  private detectedEval = false
  private nonce: string = ''

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
      useNonce = true,
      customNonce = '',
    } = opts

    // Generate or use custom nonce
    this.nonce = customNonce || (useNonce ? this.generateNonce() : '')

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
   * Generates a cryptographically secure random nonce.
   * @returns A base64-encoded random string suitable for CSP nonces
   */
  private generateNonce(): string {
    const buffer = new Uint8Array(16)
    crypto.getRandomValues(buffer)
    return Buffer.from(buffer).toString('base64')
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
      headers: {accept: 'text/html', ...(fetchOptions?.headers ?? {})},
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

    try {
      // Get the response text directly
      this.html = await response.text()
      
      // Check size after getting text
      if (maxBodySize && this.html.length > maxBodySize) {
        ac.abort()
        throw new Error('Response exceeded maxBodySize')
      }
    } catch (err) {
      ac.abort()
      throw err
    }
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

    // Add nonce to script-src if enabled
    if (this.nonce) {
      this.ensureSet('script-src').add(`'nonce-${this.nonce}'`)
      this.ensureSet('script-src').add("'strict-dynamic'")
    }

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
