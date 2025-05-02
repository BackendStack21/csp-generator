import {SecureCSPGenerator} from '../src/csp-generator'

const generator = new SecureCSPGenerator('https://21no.de', {
  allowUnsafeInlineStyle: true,
  maxBodySize: 1_000_000, // 1 MB
  timeoutMs: 10_000, // 10 seconds
  allowPrivateOrigins: false,
  requireTrustedTypes: true,
  presets: {},
})

const cspHeader = await generator.generate()
console.log('Content-Security-Policy:', cspHeader)
