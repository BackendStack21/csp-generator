import {afterEach, beforeEach, describe, expect, mock, test} from 'bun:test'
import {SecureCSPGenerator} from '../src/csp-generator'
import dns from 'dns/promises'

// Mock fetch
const originalFetch = global.fetch
let mockFetchResponse: Response | null = null

// Create a fetch mock that includes all required properties
const fetchMock = mock(async () => {
  if (!mockFetchResponse) {
    return new Response('<html></html>', {
      status: 200,
      headers: {'content-type': 'text/html'},
    })
  }
  return mockFetchResponse
}) as unknown as typeof fetch

// Store original DNS lookup function
const originalLookup = dns.lookup
// Create a mock DNS lookup function
let dnsResults: Array<{address: string; family: number}> = [
  {address: '8.8.8.8', family: 4},
]

// Override the DNS lookup function
const mockDnsLookup = async (...args: any[]) => {
  return dnsResults as any
}

describe('SecureCSPGenerator', () => {
  let mockLogger: any

  beforeEach(() => {
    // Reset mock fetch response
    mockFetchResponse = null
    global.fetch = fetchMock
    dns.lookup = mockDnsLookup

    // Reset DNS results to default public IP
    dnsResults = [{address: '8.8.8.8', family: 4}]

    // Create a mock logger
    mockLogger = {
      error: mock(() => {}),
      warn: mock(() => {}),
      info: mock(() => {}),
      debug: mock(() => {}),
    }
  })

  afterEach(() => {
    // Clean up mocks
    mock.restore()

    global.fetch = originalFetch
    dns.lookup = originalLookup
  })

  describe('constructor', () => {
    test('should throw error on empty URL', () => {
      expect(() => new SecureCSPGenerator('')).toThrow('URL must not be empty')
    })

    test('should throw error on non-HTTPS URL by default', () => {
      expect(() => new SecureCSPGenerator('http://example.com')).toThrow(
        'Insecure scheme rejected',
      )
    })

    test('should accept HTTP URL when allowHttp is true', () => {
      const generator = new SecureCSPGenerator('http://example.com', {
        allowHttp: true,
      })
      expect(generator.url.href).toBe('http://example.com/')
    })

    test('should initialize with default options', () => {
      const generator = new SecureCSPGenerator('https://example.com')
      expect(generator.url.href).toBe('https://example.com/')
    })

    test('should initialize with custom presets', () => {
      const presets = {
        'connect-src': ['https://api.example.com'],
        'script-src': ["'self'", 'https://cdn.example.com'],
      }

      const generator = new SecureCSPGenerator('https://example.com', {presets})

      // We need to test the generate method to verify presets were applied
      // This will be covered in the generate tests
    })
  })

  describe('fetchHtml', () => {
    test('should fetch HTML content successfully', async () => {
      const htmlContent =
        '<html><body><script src="https://example.com/script.js"></script></body></html>'
      mockFetchResponse = new Response(htmlContent, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('script-src')
      expect(cspHeader).toContain('https://example.com')
    })

    describe('timeout handling', () => {
      let originalSetTimeout: typeof global.setTimeout
      let originalClearTimeout: typeof global.clearTimeout
      let setTimeoutSpy: ReturnType<typeof mock>
      let clearTimeoutSpy: ReturnType<typeof mock>

      beforeEach(() => {
        originalSetTimeout = global.setTimeout
        originalClearTimeout = global.clearTimeout
        setTimeoutSpy = mock((fn: Function, ms: number) =>
          originalSetTimeout(fn, ms),
        )
        clearTimeoutSpy = mock((id?: number) => originalClearTimeout(id))
        global.setTimeout = Object.assign(setTimeoutSpy, {
          __promisify__: () => Promise.resolve(123),
        }) as unknown as typeof setTimeout
        global.clearTimeout = clearTimeoutSpy as unknown as typeof clearTimeout
      })

      afterEach(() => {
        // Restore original functions
        global.setTimeout = originalSetTimeout
        global.clearTimeout = originalClearTimeout
      })

      test('should clear timeout when fetch throws an error', async () => {
        const fetchError = new Error('Network error')
        global.fetch = mock(async () => {
          await Promise.resolve() // Make it asynchronous
          throw fetchError
        }) as unknown as typeof fetch

        const generator = new SecureCSPGenerator('https://example.com')

        await expect(generator.generate()).rejects.toThrow('Network error')
        expect(clearTimeoutSpy).toHaveBeenCalled()
      })

      test('should respect timeout and cleanup properly', async () => {
        // Mock fetch to simulate a slow response that respects AbortController
        global.fetch = mock(async (url: string, init?: RequestInit) => {
          const abortSignal = init?.signal
          await new Promise((resolve, reject) => {
            const timeout = setTimeout(() => {
              resolve(undefined)
            }, 100)

            if (abortSignal) {
              abortSignal.addEventListener('abort', () => {
                clearTimeout(timeout)
                reject(new Error('The operation was aborted'))
              })
            }
          })
          return new Response()
        }) as unknown as typeof fetch

        const generator = new SecureCSPGenerator('https://example.com', {
          timeoutMs: 50, // Set a short timeout
        })

        await expect(generator.generate()).rejects.toThrow(
          'The operation was aborted',
        )
        expect(setTimeoutSpy).toHaveBeenCalledWith(expect.any(Function), 50)
        expect(clearTimeoutSpy).toHaveBeenCalled()
      })
    })

    test('should throw error on non-200 response', async () => {
      mockFetchResponse = new Response('Not Found', {
        status: 404,
        statusText: 'Not Found',
      })

      const generator = new SecureCSPGenerator('https://example.com')
      await expect(generator.generate()).rejects.toThrow('HTTP 404 Not Found')
    })

    test('should warn on non-HTML content type', async () => {
      mockFetchResponse = new Response('{"key": "value"}', {
        status: 200,
        headers: {'content-type': 'application/json'},
      })

      const generator = new SecureCSPGenerator('https://example.com', {
        logger: mockLogger,
      })
      await generator.generate()

      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Expected HTML but got'),
      )
    })

    test('should respect maxBodySize option', async () => {
      const largeHtml = '<html>'.padEnd(10000, 'x') + '</html>'
      mockFetchResponse = new Response(largeHtml, {
        status: 200,
        headers: {'content-type': 'text/html', 'content-length': '10010'},
      })

      const generator = new SecureCSPGenerator('https://example.com', {
        maxBodySize: 5000,
      })
      await expect(generator.generate()).rejects.toThrow('Response too large')
    })
  })

  describe('parse', () => {
    test('should extract script sources', async () => {
      const html = `
        <html>
          <head>
            <script src="https://cdn.example.com/script.js"></script>
          </head>
          <body>
            <script src="https://api.example.com/analytics.js"></script>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('script-src')
      expect(cspHeader).toContain('https://cdn.example.com')
      expect(cspHeader).toContain('https://api.example.com')
    })

    test('should extract style sources', async () => {
      const html = `
        <html>
          <head>
            <link rel="stylesheet" href="https://cdn.example.com/styles.css">
          </head>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('style-src')
      expect(cspHeader).toContain('https://cdn.example.com')
    })

    test('should extract image sources', async () => {
      const html = `
        <html>
          <body>
            <img src="https://images.example.com/logo.png">
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('img-src')
      expect(cspHeader).toContain('https://images.example.com')
    })

    test('should extract frame sources', async () => {
      const html = `
        <html>
          <body>
            <iframe src="https://embed.example.com/video"></iframe>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('frame-src')
      expect(cspHeader).toContain('https://embed.example.com')
    })

    test('should extract media sources', async () => {
      const html = `
        <html>
          <body>
            <audio src="https://media.example.com/audio.mp3"></audio>
            <video src="https://media.example.com/video.mp4"></video>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('media-src')
      expect(cspHeader).toContain('https://media.example.com')
    })

    test('should handle inline scripts with hashing', async () => {
      const html = `
        <html>
          <body>
            <script>console.log("Hello, world!");</script>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('script-src')
      expect(cspHeader).toContain("'sha256-")
    })

    test('should handle inline scripts with nonce', async () => {
      const html = `
        <html>
          <body>
            <script nonce="abc123">console.log("Hello, world!");</script>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('script-src')
      expect(cspHeader).toContain("'nonce-abc123'")
    })

    test('should handle inline styles', async () => {
      const html = `
        <html>
          <head>
            <style>body { color: red; }</style>
          </head>
          <body>
            <div style="color: blue;"></div>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com', {
        allowUnsafeInlineStyle: true,
      })
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('style-src')
      expect(cspHeader).toContain("'unsafe-inline'")
    })

    test('should extract CSS URLs from inline styles', async () => {
      const html = `
        <html>
          <head>
            <style>
              @import url('https://fonts.example.com/font.css');
              body { 
                background-image: url('https://images.example.com/bg.png');
              }
            </style>
          </head>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('style-src')
      expect(cspHeader).toContain('https://fonts.example.com')
      expect(cspHeader).toContain('https://images.example.com')
    })
  })

  describe('security features', () => {
    test('should block HTTP URLs by default', async () => {
      const html = `
        <html>
          <body>
            <script src="http://insecure.example.com/script.js"></script>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).not.toContain('http://insecure.example.com')
    })

    test('should allow HTTP URLs when allowHttp is true', async () => {
      const html = `
        <html>
          <body>
            <script src="http://insecure.example.com/script.js"></script>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com', {
        allowHttp: true,
      })
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('http://insecure.example.com')
    })

    test('should block private IP origins by default', async () => {
      const html = `
        <html>
          <body>
            <script src="https://private.example.com/script.js"></script>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      // Set DNS to return a private IP
      dnsResults = [{address: '192.168.1.1', family: 4}]

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).not.toContain('https://private.example.com')
    })

    test('should allow private IP origins when allowPrivateOrigins is true', async () => {
      const html = `
        <html>
          <body>
            <script src="https://private.example.com/script.js"></script>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      // Set DNS to return a private IP
      dnsResults = [{address: '192.168.1.1', family: 4}]

      const generator = new SecureCSPGenerator('https://example.com', {
        allowPrivateOrigins: true,
      })
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('https://private.example.com')
    })

    test('should add unsafe-inline for scripts when allowUnsafeInlineScript is true', async () => {
      const html = `
        <html>
          <body>
            <script>console.log("Hello, world!");</script>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com', {
        allowUnsafeInlineScript: true,
      })
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('script-src')
      expect(cspHeader).toContain("'unsafe-inline'")
    })

    test('should add unsafe-eval when allowUnsafeEval is true', async () => {
      const html = `
        <html>
          <body>
            <script>eval("console.log('Hello, world!');");</script>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com', {
        allowUnsafeEval: true,
      })
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('script-src')
      expect(cspHeader).toContain("'unsafe-eval'")
    })

    test('should warn about eval usage when allowUnsafeEval is false', async () => {
      const html = `
        <html>
          <body>
            <script>
              eval("console.log('Hello, world!');");
              setTimeout("alert('test')", 100);
              new Function("return 'test'")();
            </script>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com', {
        logger: mockLogger,
      })
      await generator.generate()

      expect(mockLogger.warn).toHaveBeenCalledWith(
        expect.stringContaining('Detected eval-like patterns'),
      )
    })
  })

  describe('generate', () => {
    test('should include default directives', async () => {
      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain("default-src 'self'")
      expect(cspHeader).toContain("object-src 'none'")
      expect(cspHeader).toContain('upgrade-insecure-requests')
      expect(cspHeader).toContain('block-all-mixed-content')
    })

    test('should include trusted types directive when enabled', async () => {
      const generator = new SecureCSPGenerator('https://example.com', {
        requireTrustedTypes: true,
      })
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain("require-trusted-types-for 'script'")
    })

    test('should merge user presets with detected sources', async () => {
      const html = `
        <html>
          <body>
            <script src="https://cdn.example.com/script.js"></script>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const presets = {
        'script-src': ['https://api.example.com'],
        'connect-src': ['https://api.example.com'],
      }

      const generator = new SecureCSPGenerator('https://example.com', {presets})
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('script-src')
      expect(cspHeader).toContain('https://cdn.example.com')
      expect(cspHeader).toContain('https://api.example.com')
      expect(cspHeader).toContain('connect-src https://api.example.com')
    })

    test('should format the CSP header correctly', async () => {
      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      // Check format: directive values; directive values
      expect(cspHeader).toMatch(/^[a-z-]+(?: [^;]+)?(?:; [a-z-]+(?: [^;]+)?)*$/)
    })
  })
})
