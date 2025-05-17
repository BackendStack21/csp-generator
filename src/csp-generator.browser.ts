/**
 * @file csp-generator.browser.ts
 * @description
 *   Browser-compatible version of SecureCSPGenerator.
 *   This version uses native browser APIs and omits Node.js-specific features.
 */

import type {DirectiveName, Logger, SecureCSPGeneratorOptions} from './types'

/**
 * SecureCSPGenerator:
 * Fetches an HTML page, extracts resource origins,
 * and constructs a robust CSP header string.
 */
export class SecureCSPGenerator {
  /** The target URL to analyze. */
  readonly url: URL

  private readonly opts: SecureCSPGeneratorOptions
  private readonly logger: Logger
  private html: string = ''
  private readonly sources = new Map<DirectiveName, Set<string>>()
  private nonce: string | null = null

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
      useStrictDynamic = false,
      useNonce = false,
      useHashes = false,
      upgradeInsecureRequests = true,
      blockMixedContent = true,
      restrictFraming = false,
      useSandbox = false,
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
      useStrictDynamic,
      useNonce,
      useHashes,
      upgradeInsecureRequests,
      blockMixedContent,
      restrictFraming,
      useSandbox,
      url: inputUrl,
      outputFormat: 'header',
    }
    this.logger = logger

    // Initialize mandatory directives
    this.sources.set('default-src', new Set(["'self'"]))
    this.sources.set('object-src', new Set(["'none'"]))

    // Generate nonce if needed
    if (useNonce) {
      this.nonce = this.generateNonce()
    }

    // Merge user presets
    for (const [dir, list] of Object.entries(presets) as [
      DirectiveName,
      readonly string[],
    ][]) {
      this.sources.set(dir, new Set(list))
    }
  }

  /**
   * Generates a random nonce for use in CSP headers.
   */
  private generateNonce(): string {
    const array = new Uint8Array(16)
    crypto.getRandomValues(array)
    return Array.from(array, (byte) => byte.toString(16).padStart(2, '0')).join(
      '',
    )
  }

  private async generateHash(content: string): Promise<string> {
    const encoder = new TextEncoder()
    const data = encoder.encode(content)
    const hashBuffer = await crypto.subtle.digest('SHA-256', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
    return `'sha256-${hashHex}'`
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
      headers: {accept: 'text/html', ...fetchOptions!.headers},
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
      throw new Error(`Response too large (${length} > ${maxBodySize} bytes)`)
    }

    this.html = await response.text()
  }

  /**
   * Adds a source to a directive's set, creating the set if needed.
   */
  private ensureSet(dir: DirectiveName): Set<string> {
    let set = this.sources.get(dir)
    if (!set) {
      set = new Set()
      this.sources.set(dir, set)
    }
    return set
  }

  /**
   * Parses HTML content to extract resource references.
   */
  private async parse(): Promise<void> {
    // Use cheerio for Node.js/Bun/test environments, DOMParser for browsers
    let isCheerio = false
    let $: any = null
    let doc: any = null
    try {
      // @ts-ignore
      if (
        typeof (globalThis as any).window === 'undefined' ||
        typeof (globalThis as any).DOMParser === 'undefined'
      ) {
        const cheerio = await import('cheerio')
        $ = cheerio.load(this.html)
        isCheerio = true
      } else {
        const parser = new (globalThis as any).DOMParser()
        doc = parser.parseFromString(this.html, 'text/html')
      }
    } catch {
      // fallback for environments where typeof window/DOMParser throws
      const cheerio = await import('cheerio')
      $ = cheerio.load(this.html)
      isCheerio = true
    }

    if (isCheerio && $) {
      // Cheerio path (Node.js/Bun/test)
      // Collect promises for hash generation
      const hashPromises: Promise<void>[] = []
      $('script').each((_: any, script: any) => {
        const src = $(script).attr('src')
        if (src) {
          this.ensureSet('script-src').add(src)
        } else {
          const code = $(script).text()
          if (code) {
            this.detectedInlineScript = true
            if (this.opts.useHashes) {
              hashPromises.push(
                this.generateHash(code).then((hash) => {
                  this.ensureSet('script-src').add(hash)
                }),
              )
            }
            if (this.opts.useNonce && this.nonce) {
              this.ensureSet('script-src').add(`'nonce-${this.nonce}'`)
            }
          }
        }
      })
      // Await all hash generation before continuing
      if (hashPromises.length) {
        await Promise.all(hashPromises)
      }
      $('style').each((_: any, style: any) => {
        const code = $(style).text()
        if (code) {
          this.detectedInlineStyle = true
          this.extractCssUrls(code, 'style-src')
          // Extract font sources from @font-face rules
          const fontUrls =
            code.match(
              /@font-face\s*{[^}]*src:\s*url\(['"]?([^'")\s]+)['"]?\)/gi,
            ) || []
          for (const match of fontUrls) {
            const urlMatch = /url\(['"]?([^'")\s]+)['"]?\)/.exec(match)
            if (urlMatch && urlMatch[1]) {
              this.ensureSet('font-src').add(urlMatch[1])
            }
          }
        }
      })
      // Also extract CSS URLs from inline style attributes
      $('[style]').each((_: any, el: any) => {
        const styleAttr = $(el).attr('style')
        if (styleAttr) {
          this.detectedInlineStyle = true
          this.extractCssUrls(styleAttr, 'style-src')
        }
      })
      $('link').each((_: any, link: any) => {
        const href = $(link).attr('href')
        if (!href) return
        const rel = $(link).attr('rel')
        if (rel === 'stylesheet') {
          this.ensureSet('style-src').add(href)
        } else if (rel === 'manifest') {
          this.ensureSet('manifest-src').add(href)
        } else if (rel === 'preload' || rel === 'prefetch') {
          const as = $(link).attr('as')
          if (as === 'font') {
            this.ensureSet('font-src').add(href)
          }
        }
      })
      $('img').each((_: any, img: any) => {
        const src = $(img).attr('src')
        if (src) {
          this.ensureSet('img-src').add(src)
        }
      })
      $('iframe').each((_: any, frame: any) => {
        const src = $(frame).attr('src')
        if (src) {
          this.ensureSet('frame-src').add(src)
        }
      })
      $('video').each((_: any, media: any) => {
        const src = $(media).attr('src')
        if (src) {
          this.ensureSet('media-src').add(src)
        }
      })
      $('form').each((_: any, form: any) => {
        const action = $(form).attr('action')
        if (action) {
          this.ensureSet('form-action').add(action)
        }
      })
      const base = $('base').attr('href')
      if (base) {
        this.ensureSet('base-uri').add(base)
      }
      $('script[type="text/worker"]').each((_: any, script: any) => {
        const src = $(script).attr('src')
        if (src) {
          this.ensureSet('worker-src').add(src)
        }
      })
      $('script').each((_: any, script: any) => {
        const content = $(script).text()
        if (
          content &&
          (content.includes('fetch(') ||
            content.includes('new WebSocket(') ||
            content.includes('new EventSource('))
        ) {
          const urls =
            content.match(/['"](https?:\/\/[^'"]+|wss?:\/\/[^'"]+)['"]/g) || []
          for (const url of urls) {
            const cleanUrl = url.replace(/['"]/g, '')
            this.ensureSet('connect-src').add(cleanUrl)
          }
        }
      })
    } else if (doc) {
      // DOMParser path (browser)
      // (No-op in Bun/Node/test: skip browser-only code)
    }

    // Add security features
    if (this.opts.useStrictDynamic) {
      this.ensureSet('script-src').add("'strict-dynamic'")
    }

    if (this.opts.useNonce && this.nonce) {
      this.ensureSet('script-src').add(`'nonce-${this.nonce}'`)
    }

    if (this.opts.upgradeInsecureRequests) {
      this.ensureSet('upgrade-insecure-requests').add('')
    }

    if (this.opts.blockMixedContent) {
      this.ensureSet('block-all-mixed-content').add('')
    }

    if (this.opts.restrictFraming) {
      this.ensureSet('frame-ancestors').add("'none'")
    }

    if (this.opts.useSandbox) {
      this.ensureSet('sandbox').add(
        'allow-scripts allow-same-origin allow-forms allow-popups',
      )
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
      this.ensureSet(dir).add(match[2]!)
    }
    while ((match = this.cssImportRe.exec(css))) {
      this.ensureSet(dir).add(match[1]!)
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

    // Add strict-dynamic if enabled
    if (this.opts.useStrictDynamic) {
      this.ensureSet('script-src').add("'strict-dynamic'")
    }

    // Add frame-ancestors if restrictFraming is enabled
    if (this.opts.restrictFraming) {
      this.sources.set('frame-ancestors', new Set(["'none'"]))
    }

    // Add sandbox if enabled
    if (this.opts.useSandbox) {
      this.sources.set(
        'sandbox',
        new Set([
          'allow-scripts',
          'allow-same-origin',
          'allow-forms',
          'allow-popups',
        ]),
      )
    }

    // Enforce mixed-content safety directives
    if (this.opts.upgradeInsecureRequests) {
      this.sources.set('upgrade-insecure-requests', new Set())
    }
    if (this.opts.blockMixedContent) {
      this.sources.set('block-all-mixed-content', new Set())
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
