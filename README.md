# har-security-scan

Scan a HAR file for common security issues and generate a clean, self-contained HTML report.

No external dependencies. Pure Node.js.

---

## Install

```bash
npm install -g har-security-scan
```

Or run without installing:

```bash
npx har-security-scan capture.har
```

---

## Usage

```
har-security-scan <input.har> [options]

Options:
  --output, -o <file>    Output file path (default: auto-generated)
  --fail-on <severity>   Exit code 1 if findings exist at this severity or above (high|medium|low)
  --help,   -h           Show this help
```

### Basic scan

```bash
har-security-scan capture.har
```

Generates a report named `<hostname>-<timestamp>-har-security-scan.html` in the current directory.

### Custom output path

```bash
har-security-scan capture.har --output report.html
```

### CI gate

```bash
har-security-scan capture.har --fail-on high
```

Exits with code `1` if any High findings are present, making it suitable for CI pipelines.

---

## What it checks

| Check | Severity |
|---|---|
| Sensitive parameter in URL (API key, token, password) | High |
| Plain HTTP request (non-HTTPS) | High |
| Verbose error response (stack trace, SQL error) | High |
| JWT token in response body | High |
| Personal data in URL (email, NRIC, phone) | High |
| Mixed content (HTTP resources on HTTPS page) | Medium |
| Cookie missing Secure flag | Medium |
| Cookie missing HttpOnly flag | Medium |
| Missing Content-Security-Policy header | Medium |
| Missing Strict-Transport-Security header | Medium |
| Missing X-Content-Type-Options header | Medium |
| Missing X-Frame-Options header | Medium |
| Cookie missing SameSite attribute | Low |

Each finding includes a description, evidence (exact URLs and values), and an inline remediation guide with code examples for Express.js, Nginx, Django, and Spring Boot.

---

## How to export a HAR file

**Chrome / Edge:** DevTools (F12) > Network tab > right-click any request > Save all as HAR

**Firefox:** DevTools > Network tab > settings icon > Save all as HAR

**Burp Suite:** Proxy > HTTP history > select requests > right-click > Save as HAR

---

## Report

The report is a single self-contained HTML file with no external dependencies. It includes:

- Summary with finding counts by severity
- Per-finding description, evidence list, and remediation guide
- Collapsible "More detail" with framework-specific code examples
- CI-friendly `--fail-on` exit code

See [`examples/sample-report.html`](examples/sample-report.html) for an example.

---

## Examples

The `examples/` directory contains:

- `sample.har` — a realistic HAR file that triggers all checks
- `sample-report.html` — the generated report from `sample.har`

Run it yourself:

```bash
har-security-scan examples/sample.har --output my-report.html
```

---

## License

MIT — see [LICENSE](LICENSE)
