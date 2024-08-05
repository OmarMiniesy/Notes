
### General Notes

> Also known as file path traversal.
> Attacker can read arbitrary files on a server running the web application.
> Sometimes, attackers can write to files, as well as include others - [[File Inclusion]] -  allowing them to take full control.


> Images present in the directory `/var/www/images`.
---

### Reading Files

> With no input validation, any paths present on the webpage can be manipulated by using the `../` string to jump one directory above.
> The webpage is usually present in the `/var/www/` file. Going back 2 steps gives access to the root directory.
```
filename=../../etc/passwd
```
> If that doesn't work, try 3, and keep adding until it works.
> From there, any file on the system can be read.

---

### Defenses

##### Absolute Path

> Some web applications can strip the directory traversal sequences.
> This can be bypassed by using absolute paths, starting directly from root directory.
```
filename=/etc/passwd
```

##### Nested Traversal Sequences

> Using nested traversal sequences if the application strips some of the traversal sequences.
```
....// and ....\/
```
> converts to 
```
../ and ..\
```
> This works if they are stripped *non-recursively*.

##### [[Web Encoding]] the Traversal Sequence

> Using URL encoding to encode the `../` jump to `%2e%2e%2f`.
> We can also double encode the jump to `%252e%252e%252f`.

##### Validating Start of Path

> Sometimes, the application validates the start of the path.
> We can bypass this by modifying the traversal sequence to include the expected base folder.
```
filename=/var/www/images/../../../etc/passwd
```

##### Ending With Required File Type

> If a webpage requires that the filenames end with an expected file extension, we can use the null byte `%00` to terminate a path.
```
filename=../../../etc/passwd%00.png
```
> Here, we must end with a `.png`, but the null byte `%00` effectively terminates the path right before it.

---

### Preventing Directory Traversal Attacks

* Avoid passing user-supplied input into the file system, or any file system APIs.
* If that cannot be the case, implement 2 layer defense:
	1. Validate user input before processing.
	2. Append the input to the base directory, and verify that the path starts with the expected base.

---
