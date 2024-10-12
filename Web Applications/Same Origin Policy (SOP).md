### General Notes

This policy is used to prevent interaction between two webpages that come from different sources.
- Different webpages open in the same browser shouldn't be able to access data from each other, unless they have a shared [[#Origin]].

Sensitive data is sent on requests, such as [[Cookies]] and [[Sessions#Session IDs]].
- To prevent attackers from making requests and stealing this information, the Same Origin Policy is used.
- The Same Origin Policy is mainly used to restrict how a document or script loaded by one origin can interact with a resource from another origin.

> There are some [[#Exceptions]] to this restrictive policy, because if there weren't, then web applications use cases will be extremely limited.

---
### Origin

The origin of a webpage is determined by the [[Protocol]], domain name or host, and [[Port]] it uses.
- Two webpages are said to have the same origin if this information matches between both.
- If no port is specified, then it defaults to 80 for [[HTTP]] and 443 for [[HTTPS]].
- The path is not a part of the origin.

> Content from `about:blank`, `javascript:` and `data:` inherits the origin.

---
### Exceptions 

###### Cross-origin network access

Cross-origin communication is sometimes needed, and there are 3 types of this communication:
1. Cross-origin *writes*.
2. Cross-origin *reads*.
3. Cross-origin *embeddings*.

**Cross-origin Writes** are allowed, and this means when data is sent from one origin to another origin.
- Links, redirects, and form submissions are allowed between different origins.
- These requests are typically allowed, but sometimes, some request types don't work. This can be checked by sending an `OPTIONS` request to check for allowed request types.

**Cross-origin Reads** are *disallowed*, as this means data can be read between different webpages, which can expose sensitive information. However, sometimes data can be leaked:
- You can measure the dimensions of an embedded image, even if you can’t see its content.
- An embedded script can execute but won’t allow access to the details of the responses it handles.
- You can tell whether a resource exists (e.g., by trying to load it and checking for errors) even if you can’t directly read its content.

**Cross-origin Embeddings** are allowed.
- JavaScript runs with the origin of the page that loads it. For example, if you include `<script src="http://google.com/tracking.js"></script>` on `http://cs161.org`, the script has the origin of `http://cs161.org`. Now, it can interact with other scripts on `http://cs161.org`.
- Images have the origin of the page that it comes from. For example, if you include `<img src="http://google.com/logo.jpg">` on `http://cs161.org`, the image has the origin of `http://google.com`. The page that loads the image (`http://cs161.org`) only knows about the image’s dimensions when loading it.
- Frames have the origin of the URL where the frame is retrieved from, not the origin of the website that loads it. For example, if you include `<iframe src="http://google.com"></iframe>` on `http://cs161.org`, the frame has the origin of `http://google.com`.

###### `document.domain`
To allow organizations that have webpages on different subdomains to communicate with each other, a script can be used to change the origin of the webpages *only to the current domain, or to a super-domain of that domain*.
- For example, for `marketing.example.com` to read and access the content of the domain `example.com`, both of these domains need to set `document.domain = example.com`.

###### PostMessage API
This is a special function used by JavaScript to allow webpages from different origins to communicate with one another.
- To ensure that no attacker gets in the middle and manages to read the data or capture it, the sender and receiver of the data must be specified.

> [[DOM Based Vulnerabilities#Web Message Manipulation]].

###### Cross Origin Resource Sharing ([[Cross-Origin Resource Sharing (CORS)]])

Allows browsers to bypass the Same Origin Policy in a controlled manner to access resources found on other origins.
- This is done using custom [[HTTP]] headers, `acces-control-allow-origin`, which is included in the response from one website to a request coming from another website to inform the requester of the allowed origins.
- If the origins match, then the data can be sent cross origin, and the requesting browser will allow the code running on it to access the data from the fetched resource.

---
