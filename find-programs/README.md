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

```bash
pip install -r requirements.txt
```

## Configuration

Set your API keys as environment variables:

```bash
export HACKERONE_API_KEY="username:token"
export BUGCROWD_API_KEY="your_bugcrowd_api_key"
```

At least one API key must be set for the tool to work.

## Usage

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
```

Use only BugCrowd:
```bash
python xss_target_finder.py --bugcrowd --dom-based
```

### Subdomain Enumeration

Enable subdomain discovery for wildcard scopes:
```bash
python xss_target_finder.py --dom-based --subdomains
```

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

1. Fetches all public programs from configured platforms
2. Extracts URL and wildcard scope targets
3. Randomly selects programs for testing
4. For each target:
   - Detects technology stack and frameworks
   - Identifies security controls (CSP, WAF, auth)
   - Evaluates suitability for specified injection type
   - Calculates exploitability score
   - Saves promising targets to output file
5. Continues indefinitely, discovering new targets over time

## Notes

- The tool uses a headless Chrome browser for JavaScript analysis
- Random delays are included to avoid rate limiting
- Results are appended to the output file as they're discovered
- Press Ctrl+C to stop the tool gracefully

