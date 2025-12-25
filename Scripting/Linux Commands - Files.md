
A collection of some of the commands I found useful and convenient to use. Check the [[Linux Privilege Escalation]] file for scripts focusing more on security.

> Checkout this [website](https://linux.die.net/abs-guide/index.html) for a guide to bash scripting.

### Locating Files

- To locate a file : 
```bash
find /<directory> -type f -name <file-name>
```

This tries to locate a file (since `-type f` is used ) called `file-name` in a directory called `directory`.

> To locate a file with spaces in the name, escape each space with a `\`, so the file name `menu file` would become `menu\ file`.

- We can execute commands on the files we find using the `-exec` command.

- We can use expressions, such as `!`, the not operator, or `*` for wildcards while searching for files.

- We can use the `size` flag to look for files with a certain size. Check the man page for the units to use.

---
### Reading From Files

- To read a file line by line:
```bash
while IFS= read -r line; do
    echo "Text read from file: $line"
done < my_filename.txt
```

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

To deal with duplicate lines in files, use the `sort` and `uniq` tools:
```bash
cat file.txt | sort | uniq -c | sort -n
```
- The sort will first sort the lines of the file.
- The `uniq - c` will then print each duplicated line once along with its count to its left.
- The final `sort -n` will sort by the count in *ascending* order, add `-r` to sort in *descending* order. 

---
### Writing to Files

To perform regex searches and filters, the `sed` tool can be used. 

- To find duplicates in a file and replace them:
```bash
sed s/min/men/g <file-name>
```

This takes the source string after `s`, the new string to replaced after it, then finally, the number of instance to be replaced. `g` means global, so all instances, but if it is a number n, then the first n occurrences are replaced.

- To write a sequence of numbers to a file that have the same number of digits (adds 0s to the left):
```bash
seq -w <start> <end> > <file-name>
```

Specify the start and end number, and the `-w` flag is used to pad all numbers to the same length.

---
