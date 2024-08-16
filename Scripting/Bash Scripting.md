### General Notes

A shell script is simply a file containing commands that can be entered in the terminal but are grouped together to execute a larger functionality.

To write a shell script, the interpreter must be specified.
- This is done by adding the following at the beginning of the file: `#!`.
- This is then followed by the path of the shell type used, such as `/bin/bash`.

> Create a file, add the interpreter and type of shell in the beginning, and then set the execute permissions of the script file.

To add the execute permissions:
```bash
chmod +x <filename.sh>
```

Finally, to run the script file:
```shell
./<filename.sh>
```

---
### Redirecting Output

To redirect the output somewhere that it disappears:
```shell
cat file.txt > /dev/null
```
> This redirects the content of the file to disappear.

To redirect any errors that can result,  we can use the `2` file redirect.
```shell
cat file.txt 2 > /dev/null
```

---
### Dealing with Files

- To read from a file:
```shell
while read line
do 
	echo $line
done < file.txt
```

- To use the input parameters passed when running a file:
```shell
echo hi $1     #prints the first command line argument
echo hey $2     #prints the second command line argument
```

Given the input parameters when running the file: `./script.sh one two`, this will print:
```shell
hi one
hey two
```

---
### Conditionals

Expressions that produce Boolean results. 

```bash
if [ <condition> ]; then
	<statement>
elif [<condition>]; then
	<statement>
else
	<statement>
fi
```

> There needs to be proper spacing, or else it won't work. There needs to be a single space between the `[` and the first character of the condition, as well as a space between the last character and the `]`.

Single conditions can be created using the following comparators:
- Greater than          -> `-gt`
- Greater than or equal -> `-ge`
- Less than               -> `-lt`
- Less than or equal -> `-le`
- Equals                    -> `==`

Conditions can be combined using the logical operators to produce more complex conditions:
- `and` -> `-a` or `&&`
- `or`   -> `-o` or `||`
- `not` -> `!`

---
### Looping

- While loop:
```shell
while [ <condition> ]; do
	<statement>
	( <counter/update statement> )
```

- For loop:
```bash
for i in {1..5}; do
	echo $i
done
```

---
