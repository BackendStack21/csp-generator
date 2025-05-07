import {afterEach, beforeEach, describe, expect, mock, test} from 'bun:test'
import {parseArgs} from 'node:util'
import {
  formatOutput,
  getOptions,
  main,
  parseFetchOptions,
  parsePresets,
} from '../src/cli'

// Mock console.error and console.log
const originalConsoleError = console.error
const originalConsoleLog = console.log
const mockConsoleError = mock(() => {})
const mockConsoleLog = mock(() => {})

// Mock the SecureCSPGenerator class
const mockGenerate = mock(() =>
  Promise.resolve("default-src 'self'; object-src 'none'"),
)
const mockGenerator = mock(() => ({
  generate: mockGenerate,
}))

describe('CLI', () => {
  let originalProcessArgv: string[]
  let originalProcessEnv: NodeJS.ProcessEnv
  let originalProcessExit: (code?: number) => never
  let processExitCalls: number[]

  beforeEach(() => {
    // Save original process.argv and process.env
    originalProcessArgv = process.argv
    originalProcessEnv = process.env
    originalProcessExit = process.exit
    processExitCalls = []

    // Mock process.exit
    process.exit = mock((code?: number) => {
      processExitCalls.push(code ?? 0)
      return undefined as never
    })

    // Mock console methods
    console.error = mockConsoleError
    console.log = mockConsoleLog
  })

  afterEach(() => {
    // Restore original process.argv and process.env
    process.argv = originalProcessArgv
    process.env = originalProcessEnv
    process.exit = originalProcessExit
    console.error = originalConsoleError
    console.log = originalConsoleLog
    mock.restore()
  })

  describe('parseArgs', () => {
    test('should parse URL from positional argument', () => {
      process.argv = ['node', 'cli.ts', 'https://example.com']
      const {positionals} = parseArgs({
        options: {},
        allowPositionals: true,
      })
      expect(positionals[0]).toBe('https://example.com')
    })

    test('should parse boolean flags', () => {
      process.argv = [
        'node',
        'cli.ts',
        'https://example.com',
        '--allow-http',
        'true',
        '--allow-private-origins',
        'true',
      ]
      const {values} = parseArgs({
        options: {
          'allow-http': {type: 'string'},
          'allow-private-origins': {type: 'string'},
        },
        allowPositionals: true,
      })
      expect(values['allow-http']).toBe('true')
      expect(values['allow-private-origins']).toBe('true')
    })

    test('should parse numeric values', () => {
      process.argv = [
        'node',
        'cli.ts',
        'https://example.com',
        '--max-body-size',
        '1024',
        '--timeout-ms',
        '5000',
      ]
      const {values} = parseArgs({
        options: {
          'max-body-size': {type: 'string'},
          'timeout-ms': {type: 'string'},
        },
        allowPositionals: true,
      })
      expect(values['max-body-size']).toBe('1024')
      expect(values['timeout-ms']).toBe('5000')
    })

    test('should parse format option', () => {
      process.argv = [
        'node',
        'cli.ts',
        'https://example.com',
        '--format',
        'json',
      ]
      const {values} = parseArgs({
        options: {
          format: {type: 'string', short: 'f'},
        },
        allowPositionals: true,
      })
      expect(values.format).toBe('json')
    })

    test('should handle invalid format values', () => {
      process.argv = [
        'node',
        'cli.ts',
        'https://example.com',
        '--format',
        'invalid-format',
      ]
      const options = getOptions()
      expect(options.outputFormat).toBe('header') // Should default to header
    })

    test('should handle short format flag', () => {
      process.argv = ['node', 'cli.ts', 'https://example.com', '-f', 'json']
      const {values} = parseArgs({
        options: {
          format: {type: 'string', short: 'f'},
        },
        allowPositionals: true,
      })
      expect(values.format).toBe('json')
    })
  })

  describe('parsePresets', () => {
    test('should parse presets string correctly', () => {
      const presets = 'script-src:example.com,cdn.com;style-src:styles.com'
      const result = parsePresets(presets)
      expect(result).toEqual({
        'script-src': Object.freeze(['example.com', 'cdn.com']),
        'style-src': Object.freeze(['styles.com']),
      })
    })

    test('should handle empty presets', () => {
      const result = parsePresets(undefined)
      expect(result).toEqual({})
    })

    test('should handle malformed presets', () => {
      const presets = 'script-src;style-src:'
      const result = parsePresets(presets)
      expect(result).toEqual({})
    })

    test('should ignore invalid directive names', () => {
      const presets = 'invalid-directive:value1,value2;script-src:example.com'
      const result = parsePresets(presets)
      expect(result).toEqual({
        'script-src': Object.freeze(['example.com']),
      })
    })

    test('should trim whitespace from values', () => {
      const presets =
        'script-src: example.com , cdn.com ; style-src: styles.com '
      const result = parsePresets(presets)
      expect(result).toEqual({
        'script-src': Object.freeze(['example.com', 'cdn.com']),
        'style-src': Object.freeze(['styles.com']),
      })
    })

    test('should handle empty values in presets', () => {
      const presets = 'script-src:;style-src:value'
      const result = parsePresets(presets)
      expect(result).toEqual({
        'style-src': Object.freeze(['value']),
      })
    })
  })

  describe('parseFetchOptions', () => {
    test('should parse valid JSON fetch options', () => {
      const options = '{"headers":{"User-Agent":"test"}}'
      const result = parseFetchOptions(options)
      expect(result).toEqual({
        headers: {'User-Agent': 'test'},
      })
    })

    test('should handle invalid JSON', () => {
      const options = 'invalid-json'
      const result = parseFetchOptions(options)
      expect(result).toEqual({})
    })

    test('should handle undefined options', () => {
      const result = parseFetchOptions(undefined)
      expect(result).toEqual({})
    })

    test('should handle empty JSON object', () => {
      const options = '{}'
      const result = parseFetchOptions(options)
      expect(result).toEqual({})
    })

    test('should handle malformed JSON with trailing comma', () => {
      const options = '{"headers":{"User-Agent":"test"},}'
      const result = parseFetchOptions(options)
      expect(result).toEqual({})
    })
  })

  describe('formatOutput', () => {
    const csp = "default-src 'self'; object-src 'none'"

    test('should format as header', () => {
      const result = formatOutput(csp, {outputFormat: 'header'} as any)
      expect(result).toBe(
        "Content-Security-Policy: default-src 'self'; object-src 'none'",
      )
    })

    test('should format as raw', () => {
      const result = formatOutput(csp, {outputFormat: 'raw'} as any)
      expect(result).toBe("default-src 'self'; object-src 'none'")
    })

    test('should format as JSON', () => {
      const result = formatOutput(csp, {outputFormat: 'json'} as any)
      expect(result).toBe(
        JSON.stringify(
          {'Content-Security-Policy': "default-src 'self'; object-src 'none'"},
          null,
          2,
        ),
      )
    })

    test('should format as csp-only', () => {
      const result = formatOutput(csp, {outputFormat: 'csp-only'} as any)
      expect(result).toBe("default-src 'self'; object-src 'none'")
    })

    test('should default to header format', () => {
      const result = formatOutput(csp, {outputFormat: 'invalid' as any} as any)
      expect(result).toBe(
        "Content-Security-Policy: default-src 'self'; object-src 'none'",
      )
    })

    test('should handle empty CSP string', () => {
      const result = formatOutput('', {outputFormat: 'header'} as any)
      expect(result).toBe('Content-Security-Policy: ')
    })
  })

  describe('environment variables', () => {
    test('should use environment variables when no CLI options provided', () => {
      process.env.CSP_URL = 'https://example.com'
      process.env.CSP_ALLOW_HTTP = 'true'
      process.env.CSP_ALLOW_PRIVATE_ORIGINS = 'true'
      process.env.CSP_MAX_BODY_SIZE = '1024'
      process.env.CSP_TIMEOUT_MS = '5000'
      process.env.CSP_OUTPUT_FORMAT = 'json'
      process.env.CSP_PRESETS =
        'script-src:example.com,cdn.com;style-src:styles.com'

      const options = getOptions()
      expect(options).toEqual({
        url: 'https://example.com',
        allowHttp: true,
        allowPrivateOrigins: true,
        allowUnsafeInlineScript: false,
        allowUnsafeInlineStyle: false,
        allowUnsafeEval: false,
        requireTrustedTypes: true,
        maxBodySize: 1024,
        timeoutMs: 5000,
        presets: {
          'script-src': Object.freeze(['example.com', 'cdn.com']),
          'style-src': Object.freeze(['styles.com']),
        },
        fetchOptions: {},
        outputFormat: 'json',
      })
    })

    test('should prioritize CLI options over environment variables', () => {
      process.env.CSP_URL = 'https://env-example.com'
      process.env.CSP_ALLOW_HTTP = 'true'
      process.env.CSP_PRESETS = 'script-src:env-example.com'
      process.argv = [
        'node',
        'cli.ts',
        'https://cli-example.com',
        '--allow-http',
        'false',
        '--presets',
        'script-src:cli-example.com',
      ]

      const options = getOptions()
      expect(options.url).toBe('https://cli-example.com')
      expect(options.allowHttp).toBe(false)
      expect(options.presets).toEqual({
        'script-src': Object.freeze(['cli-example.com']),
      })
    })

    test('should handle invalid environment variable values', () => {
      process.env.CSP_URL = 'https://example.com'
      process.env.CSP_MAX_BODY_SIZE = 'invalid'
      process.env.CSP_TIMEOUT_MS = 'not-a-number'

      const options = getOptions()
      expect(options.maxBodySize).toBe(0) // Default value
      expect(options.timeoutMs).toBe(8000) // Default value
    })

    test('should handle empty environment variables', () => {
      process.env.CSP_URL = ''
      process.env.CSP_ALLOW_HTTP = ''
      process.env.CSP_PRESETS = ''

      const options = getOptions()
      expect(options.url).toBe('')
      expect(options.allowHttp).toBe(false)
      expect(options.presets).toEqual({})
    })
  })

  describe('main', () => {
    beforeEach(() => {
      mock.module('../src/csp-generator', () => ({
        SecureCSPGenerator: mockGenerator,
      }))
    })
    afterEach(() => {
      mock.restore()
    })

    test('should exit with error when no URL provided', async () => {
      process.argv = ['node', 'cli.ts']
      process.env = {}

      await main()

      expect(processExitCalls).toEqual([1])
      expect(mockConsoleError).toHaveBeenCalledTimes(14) // Help text has 14 lines
    })

    test('should handle successful CSP generation', async () => {
      process.argv = ['node', 'cli.ts', 'https://example.com']
      process.env = {}

      // Reset mock call counts
      mockConsoleLog.mockClear()

      await main()

      expect(mockConsoleLog).toHaveBeenCalledTimes(1)
      expect(mockConsoleLog).toHaveBeenCalledWith(
        "Content-Security-Policy: default-src 'self'; object-src 'none'",
      )
    })

    test('should handle errors during CSP generation', async () => {
      process.argv = ['node', 'cli.ts', 'https://example.com']
      process.env = {}

      // Mock generator to throw error
      mockGenerate.mockImplementationOnce(() => {
        throw new Error('Test error')
      })

      await main()

      expect(processExitCalls).toEqual([1])
      expect(mockConsoleError).toHaveBeenCalledWith('Error:', 'Test error')
    })

    test('should respect output format from CLI args', async () => {
      process.argv = [
        'node',
        'cli.ts',
        'https://example.com',
        '--format',
        'json',
      ]
      process.env = {}

      await main()

      expect(mockConsoleLog).toHaveBeenCalledWith(
        JSON.stringify(
          {
            'Content-Security-Policy': "default-src 'self'; object-src 'none'",
          },
          null,
          2,
        ),
      )
    })

    test('should handle invalid URL format', async () => {
      process.argv = ['node', 'cli.ts', 'not-a-url']
      process.env = {}

      await main()

      expect(processExitCalls).toEqual([1])
      expect(mockConsoleError).toHaveBeenCalledWith(
        'Error:',
        'Invalid URL format',
      )
    })

    test('should handle network errors', async () => {
      process.argv = ['node', 'cli.ts', 'https://example.com']
      process.env = {}

      // Mock generator to throw network error
      mockGenerate.mockImplementationOnce(() => {
        throw new Error('Network error: Failed to fetch')
      })

      await main()

      expect(processExitCalls).toEqual([1])
      expect(mockConsoleError).toHaveBeenCalledWith(
        'Error:',
        'Network error: Failed to fetch',
      )
    })

    test('should handle timeout errors', async () => {
      process.argv = ['node', 'cli.ts', 'https://example.com']
      process.env = {}

      // Mock generator to throw timeout error
      mockGenerate.mockImplementationOnce(() => {
        throw new Error('Timeout: Request took too long')
      })

      await main()

      expect(processExitCalls).toEqual([1])
      expect(mockConsoleError).toHaveBeenCalledWith(
        'Error:',
        'Timeout: Request took too long',
      )
    })
  })
})
