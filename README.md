# CSP Generator

This repository contains a Bun executable script for generating Content-Security-Policy headers using the SecureCSPGenerator module.

## Requirements

- [Bun](https://bun.sh/) - A modern JavaScript runtime that is fast and easy to use.

## Usage

```bash
# Basic usage with URL as argument
./csp-generator.js https://example.com

# Using environment variable for URL
CSP_URL=https://example.com ./csp-generator.js

# With configuration options
CSP_URL=https://example.com \
CSP_ALLOW_UNSAFE_INLINE_STYLE=true \
CSP_MAX_BODY_SIZE=1000000 \
CSP_TIMEOUT_MS=10000 \
CSP_REQUIRE_TRUSTED_TYPES=true \
./csp-generator.js
```

## Environment Variables

### Required (if not provided as command-line argument)

- `CSP_URL`: The URL to analyze and generate a CSP for

### Boolean Options (set to 'true' to enable)

- `CSP_ALLOW_HTTP`: Allow HTTP URLs in addition to HTTPS (default: false)
- `CSP_ALLOW_PRIVATE_ORIGINS`: Permit private IP / localhost origins (default: false)
- `CSP_ALLOW_UNSAFE_INLINE_SCRIPT`: Add 'unsafe-inline' to 'script-src' when inline scripts detected (default: false)
- `CSP_ALLOW_UNSAFE_INLINE_STYLE`: Add 'unsafe-inline' to 'style-src' when inline styles detected (default: false)
- `CSP_ALLOW_UNSAFE_EVAL`: Add 'unsafe-eval' to 'script-src' (default: false)
- `CSP_REQUIRE_TRUSTED_TYPES`: Add "require-trusted-types-for 'script'" to the CSP (default: false)

### Numeric Options

- `CSP_MAX_BODY_SIZE`: Maximum allowed bytes for HTML download. 0 = unlimited (default: 0)
- `CSP_TIMEOUT_MS`: Milliseconds before aborting a slow response (default: 8000)

### Complex Options

- `CSP_PRESETS`: User-provided source lists for specific directives

  - Format: `directive1:value1,value2;directive2:value3,value4`
  - Example: `CSP_PRESETS="connect-src:https://api.example.com;script-src:'self',https://cdn.example.com"`

- `CSP_FETCH_OPTIONS`: Options to forward to fetch
  - Format: JSON string
  - Example: `CSP_FETCH_OPTIONS='{"headers":{"User-Agent":"Custom Agent"}}'`

### Output Options

- `CSP_OUTPUT_FORMAT`: Format of the output (default: 'header')
  - `header`: Outputs "Content-Security-Policy: [policy]"
  - `raw`: Outputs just the policy string
  - `json`: Outputs JSON format: `{"Content-Security-Policy":"[policy]"}`

## Examples

### Basic Example

```bash
./csp-generator.js https://example.com
```

### With Presets and Custom Options

```bash
CSP_URL=https://example.com \
CSP_ALLOW_UNSAFE_INLINE_STYLE=true \
CSP_PRESETS="connect-src:https://api.example.com,https://analytics.example.com;script-src:'self',https://cdn.example.com" \
CSP_OUTPUT_FORMAT=json \
./csp-generator.js
```

### With Fetch Options

```bash
CSP_URL=https://example.com \
CSP_FETCH_OPTIONS='{"headers":{"User-Agent":"Mozilla/5.0"},"credentials":"include"}' \
./csp-generator.js
```

## Notes

- The script requires Bun to be installed and available in your PATH
- The script can be run directly with `./csp-generator.js` or with `bun csp-generator.js`
- All boolean options default to false unless explicitly set to 'true'
