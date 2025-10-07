# XSS Target Finder

A Python tool for identifying promising targets for client-side injection testing on bug bounty platforms (HackerOne and BugCrowd).

## Features

- Fetches public bug bounty programs from HackerOne and BugCrowd APIs
- Analyzes web applications to determine suitability for different XSS types
- Detects technology stacks, frameworks, and security controls
- Scores targets based on exploitability (0-100)
- Supports subdomain enumeration via certificate transparency
- Runs continuously to discover and test new targets

## Installation

### On Kali Linux (or any externally-managed Python environment)

Kali Linux uses externally-managed Python environments. The best practice is to use a virtual environment:

```bash
cd find-programs

python3 -m venv venv

source venv/bin/activate

pip install -r requirements.txt
```

To deactivate the virtual environment when done:
```bash
deactivate
```

### On other systems

If you don't have the externally-managed restriction:

```bash
pip install -r requirements.txt
```

Or use a virtual environment (recommended):

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Configuration

Set your API keys as environment variables:

```bash
export HACKERONE_API_KEY="identifier:token"
export BUGCROWD_API_KEY="your_bugcrowd_api_key"
```

At least one API key must be set for the tool to work.

### Getting Your HackerOne API Key

1. Log in to HackerOne
2. Go to Settings → API Tokens (https://hackerone.com/settings/api_token/edit)
3. Create a new API token or use an existing one
4. The format should be: `identifier:token`
   - Example: `abc123def456:1a2b3c4d5e6f7g8h9i0j`
5. Set the environment variable:
   ```bash
   export HACKERONE_API_KEY="your_identifier:your_token"
   ```

### Getting Your BugCrowd API Key

1. Log in to BugCrowd
2. Go to Settings → API
3. Generate an API token
4. Set the environment variable:
   ```bash
   export BUGCROWD_API_KEY="your_token"
   ```

## Usage

**Note:** If using a virtual environment, make sure it's activated first:
```bash
source venv/bin/activate
```

### Program Data Reuse

The tool automatically checks for existing program data files (`programs_*.json`) before fetching new data from the APIs. If found, it will prompt you:

```
Found existing program data:
  File: programs_20251006_143022.json
  Collected: 2025-10-06 14:30:22
  Programs: 150

Use this data? (y/n): 
```

- **Choose 'y'** to reuse existing data (faster, no API calls)
- **Choose 'n'** to fetch fresh data from HackerOne/BugCrowd APIs

This saves time and API rate limits if you're just testing different target criteria.

### Basic Usage

For reflected and stored XSS targets:
```bash
python xss_target_finder.py --reflected-stored
```

For DOM-based XSS and prototype pollution targets:
```bash
python xss_target_finder.py --dom-based
```

### Platform Selection

Use only HackerOne:
```bash
python xss_target_finder.py --hackerone --reflected-stored
python xss_target_finder.py -H --reflected-stored
```

Use only BugCrowd:
```bash
python xss_target_finder.py --bugcrowd --dom-based
python xss_target_finder.py -B --dom-based
```

### Subdomain Enumeration

Enable subdomain discovery for wildcard scopes:
```bash
python xss_target_finder.py --dom-based --subdomains
```

### Verbose Mode

Enable detailed output showing why each target is accepted or rejected:
```bash
python xss_target_finder.py --reflected-stored --verbose
python xss_target_finder.py --dom-based -v
```

Verbose mode shows:
- **Per Program:**
  - Number of targets extracted from each program
  - List of first 5 targets (to avoid spam)
  - Summary of URLs tested and targets found per program
- **Per Target:**
  - Detected frameworks and technologies
  - Number of JavaScript files
  - Security controls (CSP, WAF, authentication)
  - Detailed reason for acceptance/rejection
  - Individual target scores
  - Which URLs are being skipped (already tested)
- **Error Details:**
  - Full stack traces for debugging issues

## Output

The tool generates two types of output files:

1. **Program Data**: `programs_YYYYMMDD_HHMMSS.json`
   - Contains all fetched program data and scope information

2. **Target Results**: `xss_targets_{type}_YYYYMMDD_HHMMSS.txt`
   - Lists discovered targets with scores
   - Format: `https://example.com -- 85`

## Target Selection Criteria

### Reflected/Stored XSS (`--reflected-stored`)
- Targets WITHOUT virtual DOM frameworks (React, Vue, Angular)
- Simpler JavaScript implementations
- Traditional server-side rendered applications

### DOM-based XSS (`--dom-based`)
- Targets WITH significant custom JavaScript
- Applications using frameworks with exposed webpack bundles
- Complex client-side JavaScript implementations

## Scoring System

Targets are scored from 0-100 based on:

**Positive Factors:**
- No or weak Content Security Policy
- Lack of Web Application Firewall
- No authentication required
- Exposed webpack modules (for DOM-based)
- Custom JavaScript (for DOM-based)

**Negative Factors:**
- Strict Content Security Policy
- Web Application Firewall detected
- Authentication required
- Strong security headers

## How It Works

1. Checks for existing program data and prompts user to reuse or fetch fresh
2. Fetches all public programs from configured platforms (if needed)
3. Extracts URL and wildcard scope targets
4. Randomly selects programs for testing
5. For each target:
   - Detects technology stack and frameworks
   - Identifies security controls (CSP, WAF, auth)
   - Evaluates suitability for specified injection type
   - Calculates exploitability score
   - Saves promising targets to output file
6. Continues indefinitely with robust error handling
7. Handles connection errors gracefully without stopping

## Notes

- The tool uses a headless Chrome browser for JavaScript analysis (optional but recommended)
  - If ChromeDriver fails to initialize, the tool continues without browser-based checks
  - Webpack exposure detection requires a working browser setup
- Random delays are included to avoid rate limiting
- Results are appended to the output file as they're discovered
- Press Ctrl+C to stop the tool gracefully
- Connection errors during target testing are handled automatically - the tool continues running
- Program data can be reused to save time and avoid unnecessary API calls
- Each run creates a new results file with a unique timestamp
- **The tool automatically prevents your system from going to sleep while running** - sleep mode is restored when you stop the tool

## Troubleshooting

### ChromeDriver - Now Automatic! 🎉

The tool now **automatically downloads the correct ChromeDriver** version for your Chrome/Chromium browser!

- Detects your Chrome/Chromium version
- Downloads the matching ChromeDriver from official sources
- Caches it in `~/.chromedriver/vXXX/` for reuse
- Works with any version (115+), including the latest Chromium 139

**Just run the tool** and it will handle everything automatically on first run.

If you have issues:
```bash
rm -rf ~/.chromedriver/
rm -rf ~/.wdm/drivers/chromedriver
```

Then restart the tool - it will download fresh drivers.

