#!/usr/bin/env bun

/**
 * @file cli.ts
 * @description Command-line interface for the CSP generator
 */

import type {SecureCSPGeneratorOptions} from './types'
import {SecureCSPGenerator} from './csp-generator'
import {parseArgs} from 'node:util'
import {VALID_CSP_DIRECTIVES, type CSPDirective} from './constants'

export function parsePresets(
  value: string | undefined,
): Partial<Record<CSPDirective, readonly string[]>> {
  if (!value) return {}
  const presets: Partial<Record<CSPDirective, readonly string[]>> = {}
  value.split(';').forEach((preset) => {
    const [directive, values] = preset.split(':')
    if (directive && values) {
      const trimmedDirective = directive.trim() as CSPDirective
      if (VALID_CSP_DIRECTIVES.includes(trimmedDirective)) {
        presets[trimmedDirective] = Object.freeze(
          values.split(',').map((v) => v.trim()),
        )
      }
    }
  })
  return presets
}

export function parseFetchOptions(
  value: string | undefined,
): Record<string, any> {
  if (!value) return {}
  try {
    return JSON.parse(value)
  } catch {
    return {}
  }
}

export function formatOutput(
  csp: string,
  options: SecureCSPGeneratorOptions,
): string {
  switch (options.outputFormat) {
    case 'json':
      return JSON.stringify({'Content-Security-Policy': csp}, null, 2)
    case 'raw':
    case 'csp-only':
      return csp
    case 'header':
    default:
      return `Content-Security-Policy: ${csp}`
  }
}

export function getOptions(): SecureCSPGeneratorOptions {
  const {
    values: {
      'allow-http': allowHttp,
      'allow-private-origins': allowPrivateOrigins,
      'allow-unsafe-inline-script': allowUnsafeInlineScript,
      'allow-unsafe-inline-style': allowUnsafeInlineStyle,
      'allow-unsafe-eval': allowUnsafeEval,
      'require-trusted-types': requireTrustedTypes,
      'max-body-size': maxBodySize,
      'timeout-ms': timeoutMs,
      presets,
      'fetch-options': fetchOptions,
      format,
    },
    positionals,
  } = parseArgs({
    options: {
      'allow-http': {type: 'string'},
      'allow-private-origins': {type: 'string'},
      'allow-unsafe-inline-script': {type: 'string'},
      'allow-unsafe-inline-style': {type: 'string'},
      'allow-unsafe-eval': {type: 'string'},
      'require-trusted-types': {type: 'string'},
      'max-body-size': {type: 'string'},
      'timeout-ms': {type: 'string'},
      presets: {type: 'string'},
      'fetch-options': {type: 'string'},
      format: {type: 'string', short: 'f'},
    },
    allowPositionals: true,
  })

  const finalUrl = positionals[0] || process.env.CSP_URL || ''

  const parseBoolean = (
    value: string | undefined,
    envVar: string | undefined,
  ) => {
    if (value !== undefined) return value === 'true'
    return envVar === 'true'
  }

  const parseNumber = (
    value: string | undefined,
    envVar: string | undefined,
    defaultValue: number,
  ) => {
    const val = value || envVar
    if (!val) return defaultValue
    const num = parseInt(val, 10)
    return isNaN(num) ? defaultValue : num
  }

  return {
    url: finalUrl,
    allowHttp: parseBoolean(allowHttp, process.env.CSP_ALLOW_HTTP),
    allowPrivateOrigins: parseBoolean(
      allowPrivateOrigins,
      process.env.CSP_ALLOW_PRIVATE_ORIGINS,
    ),
    allowUnsafeInlineScript: parseBoolean(
      allowUnsafeInlineScript,
      process.env.CSP_ALLOW_UNSAFE_INLINE_SCRIPT,
    ),
    allowUnsafeInlineStyle: parseBoolean(
      allowUnsafeInlineStyle,
      process.env.CSP_ALLOW_UNSAFE_INLINE_STYLE,
    ),
    allowUnsafeEval: parseBoolean(
      allowUnsafeEval,
      process.env.CSP_ALLOW_UNSAFE_EVAL,
    ),
    requireTrustedTypes: parseBoolean(
      requireTrustedTypes,
      process.env.CSP_REQUIRE_TRUSTED_TYPES,
    ),
    maxBodySize: parseNumber(maxBodySize, process.env.CSP_MAX_BODY_SIZE, 0),
    timeoutMs: parseNumber(timeoutMs, process.env.CSP_TIMEOUT_MS, 8000),
    presets: parsePresets(presets || process.env.CSP_PRESETS),
    fetchOptions: parseFetchOptions(
      fetchOptions || process.env.CSP_FETCH_OPTIONS,
    ),
    outputFormat: (format ||
      process.env.CSP_OUTPUT_FORMAT ||
      'header') as SecureCSPGeneratorOptions['outputFormat'],
  }
}

export async function main() {
  const options = getOptions()

  if (!options.url) {
    console.error('Usage: csp-generator <url> [options]')
    console.error('\nOptions:')
    console.error(
      '  --allow-http <true|false>       Allow HTTP URLs in addition to HTTPS',
    )
    console.error(
      '  --allow-private-origins <true|false>  Permit private IP / localhost origins',
    )
    console.error(
      '  --allow-unsafe-inline-script <true|false>  Add unsafe-inline to script-src',
    )
    console.error(
      '  --allow-unsafe-inline-style <true|false>  Add unsafe-inline to style-src',
    )
    console.error(
      '  --allow-unsafe-eval <true|false>  Add unsafe-eval to script-src',
    )
    console.error(
      '  --require-trusted-types <true|false>  Add require-trusted-types-for script',
    )
    console.error(
      '  --max-body-size <bytes>        Maximum allowed bytes for HTML download',
    )
    console.error('  --timeout-ms <milliseconds>    Timeout for fetch requests')
    console.error('  --presets <presets>            User-provided source lists')
    console.error(
      '  --fetch-options <json>         Options to forward to fetch',
    )
    console.error(
      '  --format, -f <format>          Output format (header, raw, json, csp-only)',
    )
    console.error('\nExample: csp-generator https://example.com --format json')
    process.exit(1)
  }

  try {
    const generator = new SecureCSPGenerator(options.url, {
      allowHttp: options.allowHttp,
      allowPrivateOrigins: options.allowPrivateOrigins,
      allowUnsafeInlineScript: options.allowUnsafeInlineScript,
      allowUnsafeInlineStyle: options.allowUnsafeInlineStyle,
      allowUnsafeEval: options.allowUnsafeEval,
      requireTrustedTypes: options.requireTrustedTypes,
      maxBodySize: options.maxBodySize,
      timeoutMs: options.timeoutMs,
      presets: options.presets,
      fetchOptions: options.fetchOptions,
    })

    const csp = await generator.generate()
    console.log(formatOutput(csp, options))
  } catch (error: any) {
    console.error('Error:', error)
    process.exit(1)
  }
}

// Only run main() if this is the main module
if (import.meta.main) {
  main()
}
