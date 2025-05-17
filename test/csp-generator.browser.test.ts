// noinspection JSUnresolvedLibraryURL,CssOverwrittenProperties,HtmlRequiredAltAttribute

import {describe, test, expect, beforeEach, mock, afterEach} from 'bun:test'
import {SecureCSPGenerator} from '../src/csp-generator.browser'

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

describe('SecureCSPGenerator (browser)', () => {
  let mockLogger: any
  let dom: any

  beforeEach(() => {
    // Reset mock fetch response
    mockFetchResponse = null
    global.fetch = fetchMock

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

    // Restore original fetch if needed
    global.fetch = originalFetch
  })

  describe('browser-specific features', () => {
    test('should extract font sources', async () => {
      const html = `
        <html>
          <head>
            <link rel="stylesheet" href="https://fonts.example.com/styles.css">
            <style>
              @font-face {
                font-family: 'Custom Font';
                src: url('https://fonts.example.com/font.woff2') format('woff2');
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

      expect(cspHeader).toContain('font-src')
      expect(cspHeader).toContain('https://fonts.example.com')
    })

    test('should extract connect sources', async () => {
      const html = `
        <html>
          <body>
            <script>
              fetch('https://api.example.com/data');
              new WebSocket('wss://ws.example.com');
            </script>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('connect-src')
      expect(cspHeader).toContain('https://api.example.com')
      expect(cspHeader).toContain('wss://ws.example.com')
    })

    test('should extract form action sources', async () => {
      const html = `
        <html>
          <body>
            <form action="https://forms.example.com/submit"></form>
          </body>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('form-action')
      expect(cspHeader).toContain('https://forms.example.com')
    })

    test('should extract base URI', async () => {
      const html = `
        <html>
          <head>
            <base href="https://base.example.com/">
          </head>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('base-uri')
      expect(cspHeader).toContain('https://base.example.com')
    })

    test('should extract manifest source', async () => {
      const html = `
        <html>
          <head>
            <link rel="manifest" href="https://example.com/manifest.json">
          </head>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('manifest-src')
      expect(cspHeader).toContain('https://example.com')
    })

    test('should extract worker sources', async () => {
      const html = `
        <html>
          <head>
            <script type="text/worker" src="https://workers.example.com/worker.js"></script>
          </head>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('worker-src')
      expect(cspHeader).toContain('https://workers.example.com')
    })
  })

  describe('browser-specific security features', () => {
    test('should handle strict-dynamic', async () => {
      const generator = new SecureCSPGenerator('https://example.com', {
        useStrictDynamic: true,
      })
      const cspHeader = await generator.generate()
      expect(cspHeader).toContain("'strict-dynamic'")
    })

    test('should handle nonce generation', async () => {
      const generator = new SecureCSPGenerator('https://example.com', {
        useNonce: true,
      })
      const cspHeader = await generator.generate()
      expect(cspHeader).toMatch(/'nonce-[a-f0-9]{32}'/)
    })

    test('should handle hash generation', async () => {
      const html = `
        <html>
          <head>
            <script>
              console.log('test script');
            </script>
          </head>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com', {
        useHashes: true,
      })
      const cspHeader = await generator.generate()
      expect(cspHeader).toMatch(/'sha256-[a-f0-9]{64}'/)
    })

    test('should handle upgrade-insecure-requests', async () => {
      const generator = new SecureCSPGenerator('https://example.com', {
        upgradeInsecureRequests: true,
      })
      const cspHeader = await generator.generate()
      expect(cspHeader).toContain('upgrade-insecure-requests')
    })

    test('should handle block-all-mixed-content', async () => {
      const generator = new SecureCSPGenerator('https://example.com', {
        blockMixedContent: true,
      })
      const cspHeader = await generator.generate()
      expect(cspHeader).toContain('block-all-mixed-content')
    })

    test('should handle frame-ancestors', async () => {
      const generator = new SecureCSPGenerator('https://example.com', {
        restrictFraming: true,
      })
      const cspHeader = await generator.generate()
      expect(cspHeader).toContain('frame-ancestors')
    })

    test('should handle sandbox', async () => {
      const generator = new SecureCSPGenerator('https://example.com', {
        useSandbox: true,
      })
      const cspHeader = await generator.generate()
      expect(cspHeader).toContain('sandbox')
    })

    test('should extract CSS URLs with different formats', async () => {
      const html = `
        <html>
          <head>
            <style>
              @import url('https://styles1.example.com/main.css');
              @import "https://styles2.example.com/theme.css";
              body {
                background: url(https://images.example.com/bg.jpg);
                background-image: url("https://images.example.com/pattern.png");
              }
              @font-face {
                font-family: 'Test Font';
                src: url('https://fonts.example.com/test.woff2') format('woff2'),
                     url('https://fonts.example.com/test.woff') format('woff');
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
      expect(cspHeader).toContain('https://styles1.example.com')
      expect(cspHeader).toContain('https://styles2.example.com')
      expect(cspHeader).toContain('https://images.example.com')
      expect(cspHeader).toContain('font-src')
      expect(cspHeader).toContain('https://fonts.example.com')
    })

    test('should handle fetch timeout', async () => {
      // Override fetch to simulate timeout
      global.fetch = mock(async () => {
        await new Promise((_, reject) =>
          setTimeout(() => reject(new Error('The operation was aborted')), 200),
        )
      }) as unknown as typeof fetch

      const generator = new SecureCSPGenerator('https://example.com', {
        timeoutMs: 100,
      })

      await expect(generator.generate()).rejects.toThrow(
        'The operation was aborted',
      )
    })

    test('should handle invalid content-type', async () => {
      mockFetchResponse = new Response('<html></html>', {
        status: 200,
        headers: {'content-type': 'application/json'},
      })

      const generator = new SecureCSPGenerator('https://example.com', {
        logger: mockLogger,
      })
      await generator.generate()

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Expected HTML but got application/json',
      )
    })

    test('should handle preload and prefetch links', async () => {
      const html = `
        <html>
          <head>
            <link rel="preload" href="https://fonts.example.com/font.woff2" as="font" crossorigin>
            <link rel="prefetch" href="https://images.example.com/large.jpg" as="image">
            <link rel="preload" href="https://scripts.example.com/main.js" as="script">
            <script src="https://scripts.example.com/main.js"></script>
          </head>
        </html>
      `

      mockFetchResponse = new Response(html, {
        status: 200,
        headers: {'content-type': 'text/html'},
      })

      const generator = new SecureCSPGenerator('https://example.com')
      const cspHeader = await generator.generate()

      expect(cspHeader).toContain('font-src')
      expect(cspHeader).toContain('https://fonts.example.com')
      expect(cspHeader).toContain('script-src')
      expect(cspHeader).toContain('https://scripts.example.com')
    })

    test('should handle multiple inline styles with different formats', async () => {
      const html = `
        <html>
          <head>
            <style>
              @import url(https://cdn1.example.com/style1.css);
            </style>
            <style>
              @import "https://cdn2.example.com/style2.css";
            </style>
            <style>
              div { background: url('https://cdn3.example.com/bg.jpg'); }
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
      expect(cspHeader).toContain('https://cdn1.example.com')
      expect(cspHeader).toContain('https://cdn2.example.com')
      expect(cspHeader).toContain('https://cdn3.example.com')
    })
  })
})
