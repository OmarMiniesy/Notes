
### General Notes

> OS command injecction allows attackers to execute operating system commands on the server running a web application.
> Can be used to compromise the hosting infrastructure and exploit relationships to pivot the attack.

---

### Shell Characters

* `&` : First command in the background, and the second command running simultaneously.
* `&&`: Will execute the second command if the first one works.
* `|`: Will take the output from the first command and execute the second command.
* `||`: If the first command fails, the second one is executed.

---

### Injection

> Identifying points in the website where user input has access to backend server/database.
> If the application executes a shell command and returns the raw output.
> Using the `&` operator, can execute multiple commands at the same time.
```
& whoami &
```
> The `&` at the end because it separates the injected command from whatever follows.
> URL [[Web Encoding]] can be used on this payload.

> Make sure to differentiate between this `&` and the `&` in the URL for adding multiple parameters.

#### Blind Injections

> The output of the command isn't seen in the [[HTTP]] response .

> Can use a time delay.
```
& ping -c 10 127.0.0.1 &
```
> The `ping` command is useful as it will work here for 10 seconds, therefore our command will return a response after 10 seconds.

> The output can be redirected into a file in the web application with open access from the browser.
> Can write into the `static` directory.
```
/var/www/static/<file-name>
& whoami > /var/wwww/static/whoami.txt &
```
> This `whoami.txt` file can then be seen by adding it in the URL.
```
https://<URL>/whoami.txt
```

---

### Useful Commands

> Useful commands to execute if an injection is discovered.

* `whoami` for the user.
* `uname -a` for the OS.
* `ifconfig` for the network. [[Networking/Routing|Routing]]
* `netstat -an` for the network connections. [[Port]]
* `ps ef` for the running processes. 

---

### Preventing Command Injection Attacks

* Never call out to OS commands from application layer.
* If that is not the case, then strong input validationr required.
	* Validating against whitelist.
	* Validating data type.

---
