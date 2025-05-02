#!/usr/bin/env bun

/**
 * CSP Generator Bun Executable
 *
 * This script uses the SecureCSPGenerator module to generate a Content-Security-Policy header
 * for a given URL. All configuration parameters can be passed as environment variables.
 *
 * Usage:
 *   ./csp-generator.js <url>
 *
 * Or with environment variables:
 *   CSP_URL=https://example.com CSP_ALLOW_UNSAFE_INLINE_STYLE=true ./csp-generator.js
 */

import {SecureCSPGenerator} from './src/csp-generator'

// Get the URL from command line arguments or environment variable
const args = process.argv.slice(2)
const url = args[0] || process.env.CSP_URL

if (!url) {
  console.error(
    'Error: URL is required. Provide it as the first argument or set CSP_URL environment variable.',
  )
  console.error('Usage: ./csp-generator.js <url>')
  console.error('Example: ./csp-generator.js https://example.com')
  console.error('Or: CSP_URL=https://example.com ./csp-generator.js')
  process.exit(1)
}

/**
 * Parse presets from environment variable
 * Format: directive1:value1,value2;directive2:value3,value4
 */
function parsePresets() {
  const presetsEnv = process.env.CSP_PRESETS
  if (!presetsEnv) return {}

  try {
    const presets = {}

    // Split by semicolon to get each directive
    const directives = presetsEnv.split(';')

    for (const directive of directives) {
      // Find the first colon which separates directive name from values
      const colonIndex = directive.indexOf(':')
      if (colonIndex === -1) continue

      const name = directive.substring(0, colonIndex).trim()
      const valuesStr = directive.substring(colonIndex + 1).trim()

      // Split values by comma
      const valueArray = valuesStr.split(',').map((v) => v.trim())

      // Store in presets object
      presets[name] = valueArray
    }

    return presets
  } catch (error) {
    console.error('Error parsing CSP_PRESETS:', error.message)
    return {}
  }
}

/**
 * Parse fetch options from environment variable
 * Format: JSON string
 */
function parseFetchOptions() {
  const fetchOptsEnv = process.env.CSP_FETCH_OPTIONS
  if (!fetchOptsEnv) return {}

  try {
    return JSON.parse(fetchOptsEnv)
  } catch (error) {
    console.error('Error parsing CSP_FETCH_OPTIONS:', error.message)
    return {}
  }
}

// Build configuration object from environment variables
const config = {
  // Boolean options
  allowHttp: process.env.CSP_ALLOW_HTTP === 'true',
  allowPrivateOrigins: process.env.CSP_ALLOW_PRIVATE_ORIGINS === 'true',
  allowUnsafeInlineScript:
    process.env.CSP_ALLOW_UNSAFE_INLINE_SCRIPT === 'true',
  allowUnsafeInlineStyle: process.env.CSP_ALLOW_UNSAFE_INLINE_STYLE === 'true',
  allowUnsafeEval: process.env.CSP_ALLOW_UNSAFE_EVAL === 'true',
  requireTrustedTypes: process.env.CSP_REQUIRE_TRUSTED_TYPES === 'true',

  // Numeric options
  maxBodySize: process.env.CSP_MAX_BODY_SIZE
    ? parseInt(process.env.CSP_MAX_BODY_SIZE, 10)
    : 0,
  timeoutMs: process.env.CSP_TIMEOUT_MS
    ? parseInt(process.env.CSP_TIMEOUT_MS, 10)
    : 8000,

  // Complex options
  presets: parsePresets(),
  fetchOptions: parseFetchOptions(),
}

// Filter out undefined values
const filteredConfig = Object.fromEntries(
  Object.entries(config).filter(([_, value]) => value !== undefined),
)

// Main function to generate CSP header
async function generateCSP() {
  try {
    // Create generator with URL and configuration
    const generator = new SecureCSPGenerator(url, filteredConfig)

    // Generate CSP header
    const cspHeader = await generator.generate()

    // Output format based on environment variable
    const outputFormat = process.env.CSP_OUTPUT_FORMAT || 'header'

    switch (outputFormat.toLowerCase()) {
      case 'json':
        console.log(JSON.stringify({'Content-Security-Policy': cspHeader}))
        break
      case 'raw':
        console.log(cspHeader)
        break
      case 'header':
      default:
        console.log('Content-Security-Policy:', cspHeader)
        break
    }
  } catch (error) {
    console.error('Error generating CSP header:', error.message)
    process.exit(1)
  }
}

// Run the generator
generateCSP()
