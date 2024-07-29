
A collection of some of the commands I found useful and convenient to use. Check the [[Linux Privilege Escalation]] file for scripts focusing more on security.

### Locating Files

- To locate a file : 
```bash
find /<directory> -type f -name <file-name>
```

This tries to locate a file (since `-type f` is used )called `file-name` in a directory called `directory`.

---
### Reading From Files

- To read a specific number of lines from the beginning or the end of a file:
```bash
head -n <file-path>
tail -n <file-path>
```

Where `n` is the number of lines to print. The default is 10.

- To start reading from a specific line:
```bash
tail -n+NUM <file-path>  ## print everything after
head -n-NUM <file-path>  ## print everything before
```

Where `NUM` is the line number.

- To display a file in the terminal with the line numbers, use the `nl` command.
```bash
nl <file-path>
```

Combining these commands can help in a chunk of lines that are around a desired line in a large file.
- First, find the line number that has the desired text using: `nl <file-name> | grep <desired_text>`.
- To print `x` lines before that line number `y`, we use: `head -n-y | tail -nx`.
- To print `x` lines after that line number `y`, we use: `tail -n+y | head -nx`.

---
### Writing to Files

To perform regex searches and filters, the `sed` tool can be used. 

- To find duplicates in a file and replace them:
```bash
sed s/min/men/g <file-name>
```

This takes the source string after `s`, the new string to replaced after it, then finally, the number of instance to be replaced. `g` means global, so all instances, but if it is a number n, then the first n occurrences are replaced.

---
