# CSP Generator

A robust Content Security Policy (CSP) generator that works in both Node.js and browser environments. This tool analyzes HTML content and generates appropriate CSP headers to enhance your application's security.

## Requirements

- [Bun](https://bun.sh/) - A modern JavaScript runtime that is fast and easy to use.

## Installation

```bash
# Install globally
bun install -g csp-generator

# Or install locally in your project
bun add csp-generator
```

## Usage

```bash
# If installed globally
csp-generator https://example.com

# If installed locally (using npx)
bunx csp-generator https://example.com

# If you downloaded the source code
bun src/cli.ts https://example.com

# Using environment variable for URL
CSP_URL=https://example.com csp-generator

# With configuration options
CSP_URL=https://example.com \
CSP_ALLOW_UNSAFE_INLINE_STYLE=true \
CSP_MAX_BODY_SIZE=1000000 \
CSP_TIMEOUT_MS=10000 \
CSP_REQUIRE_TRUSTED_TYPES=true \
csp-generator
```

## CLI Parameters

The CSP generator supports the following command-line parameters:

```bash
csp-generator <url> [options]
```

### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--allow-http` | boolean | false | Allow HTTP URLs in addition to HTTPS |
| `--allow-private-origins` | boolean | false | Permit private IP / localhost origins |
| `--allow-unsafe-inline-script` | boolean | false | Add 'unsafe-inline' to 'script-src' when inline scripts detected |
| `--allow-unsafe-inline-style` | boolean | false | Add 'unsafe-inline' to 'style-src' when inline styles detected |
| `--allow-unsafe-eval` | boolean | false | Add 'unsafe-eval' to 'script-src' |
| `--require-trusted-types` | boolean | false | Add "require-trusted-types-for 'script'" to the CSP |
| `--use-strict-dynamic` | boolean | false | Add 'strict-dynamic' to script-src |
| `--use-nonce` | boolean | false | Generate and use nonces for inline scripts |
| `--use-hashes` | boolean | false | Generate hashes for inline content |
| `--upgrade-insecure-requests` | boolean | true | Force HTTPS upgrades |
| `--block-mixed-content` | boolean | true | Block mixed content |
| `--restrict-framing` | boolean | true | Add frame-ancestors 'none' |
| `--use-sandbox` | boolean | false | Add sandbox directive with safe defaults |
| `--max-body-size` | number | 0 | Maximum allowed bytes for HTML download (0 = unlimited) |
| `--timeout-ms` | number | 8000 | Timeout for fetch requests in milliseconds |
| `--format`, `-f` | string | 'header' | Output format: header, raw, json, csp-only |
| `--presets` | string | - | User-provided source lists (format: "directive1:value1,value2;directive2:value3,value4") |
| `--fetch-options` | JSON | - | Custom fetch options as JSON string |

### Examples

Generate CSP with default settings:
```bash
csp-generator https://example.com
```

Enable unsafe inline styles and strict dynamic:
```bash
csp-generator https://example.com \
  --allow-unsafe-inline-style true \
  --use-strict-dynamic true
```

Output as JSON with custom presets:
```bash
csp-generator https://example.com \
  --format json \
  --presets "script-src:https://cdn.example.com;connect-src:https://api.example.com"
```

## Environment Variables Configuration

The CSP generator uses Bun's built-in support for environment variables. It automatically loads variables from:
- `.env`
- `.env.local`
- `.env.${NODE_ENV}` (e.g., `.env.development`, `.env.production`)
- `.env.${NODE_ENV}.local`

To get started:

1. Copy the example environment file:
```bash
cp .env.example .env
```

2. Edit the `.env` file with your desired configuration:
```env
# Required (if not using command-line argument)
CSP_URL=https://your-site.com

# Enable specific features
CSP_ALLOW_UNSAFE_INLINE_STYLE=true
CSP_USE_STRICT_DYNAMIC=true
```

3. Run the generator:
```bash
csp-generator
```

All command-line options have equivalent environment variables. This is particularly useful for:
- CI/CD pipelines
- Docker environments
- Development configurations
- Shared team settings

> Note: No additional packages are needed for .env support as it's built into Bun.

## Browser Usage

You can also use the CSP generator directly in your browser:

```html
<script type="module">
  import { CSPGenerator } from 'csp-generator/browser';

  // Create a new instance
  const generator = new CSPGenerator({
    // Optional configuration
    allowUnsafeInlineStyle: true,
    useStrictDynamic: true
  });

  // Generate CSP for a URL
  const result = await generator.generate('https://example.com');
  console.log(result);

  // Or analyze HTML content directly
  const htmlContent = document.documentElement.outerHTML;
  const result = await generator.analyze(htmlContent);
  console.log(result);
</script>
```

The browser version provides the same functionality as the CLI but uses native browser APIs for better performance. It's particularly useful for:
- Generating CSPs for single-page applications
- Testing CSPs against your current page
- Integrating CSP generation into your web development workflow

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

### Security Options

- `CSP_USE_STRICT_DYNAMIC`: Add 'strict-dynamic' to script-src (default: false)
- `CSP_USE_NONCE`: Generate and use nonces for inline scripts (default: false)
- `CSP_USE_HASHES`: Generate hashes for inline content (default: false)
- `CSP_UPGRADE_INSECURE_REQUESTS`: Force HTTPS upgrades (default: true)
- `CSP_BLOCK_MIXED_CONTENT`: Block mixed content (default: true)
- `CSP_RESTRICT_FRAMING`: Add frame-ancestors 'none' (default: true)
- `CSP_USE_SANDBOX`: Add sandbox directive with safe defaults (default: false)

### Numeric Options

- `CSP_MAX_BODY_SIZE`: Maximum allowed bytes for HTML download. 0 = unlimited (default: 0)
- `CSP_TIMEOUT_MS`: Milliseconds before aborting a slow response (default: 8000)

### Complex Options

- `CSP_PRESETS`: User-provided source lists for specific directives

  - Format: `directive1:value1,value2;directive2:value3,value4`
  - Example: `CSP_PRESETS="connect-src:https://api.example.com,wss://ws.example.com;font-src:https://fonts.example.com"`

- `CSP_FETCH_OPTIONS`: Options to forward to fetch
  - Format: JSON string
  - Example: `CSP_FETCH_OPTIONS='{"headers":{"User-Agent":"Custom Agent"}}'`

### Output Options

- `CSP_OUTPUT_FORMAT`: Format of the output (default: 'header')
  - `header`: Outputs "Content-Security-Policy: [policy]"
  - `raw`: Outputs just the policy string
  - `json`: Outputs JSON format: `{"Content-Security-Policy":"[policy]"}`
  - `csp-only`: Outputs just the CSP directives

## Features

The generator automatically detects and includes various resource types:

1. **Scripts**
   - External script sources
   - Inline scripts (with hash/nonce)
   - Worker scripts
   - Module scripts

2. **Styles**
   - External stylesheets
   - Inline styles
   - CSS @import rules
   - CSS url() functions

3. **Fonts**
   - Font files from @font-face rules
   - Preloaded fonts
   - Google Fonts and other CDNs

4. **Network**
   - Fetch API calls
   - WebSocket connections
   - EventSource connections
   - XMLHttpRequest (legacy)

5. **Media**
   - Images
   - Videos
   - Audio
   - Media source extensions

6. **Frames**
   - iframes
   - frame-ancestors
   - Sandbox controls

## Notes

- The package requires Bun to be installed and available in your PATH
- After installation, use `csp-generator` command directly
- For local development, use `bun src/cli.ts`
- All boolean options default to false unless explicitly set to 'true'
- The generator supports both Node.js and browser environments
- Font sources are automatically detected from @font-face rules
- WebSocket URLs are detected in script content
- The browser version uses native APIs for better performance

## Development

```bash
# Install dependencies
bun install

# Build the package
bun run build

# Run tests
bun test

# Run linting
bun run lint

# Format code
bun run format

# Try the CLI locally during development
bun src/cli.ts https://example.com
```

## License

MIT
