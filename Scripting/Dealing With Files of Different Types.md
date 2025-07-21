
### Zip files

- We can unzip zipped files using the command:
```bash
7z e <zip-file>
```

> If we cannot because it is password, we can use [[John the Ripper#zip2john]].

---
### Images

- We can use the `exiftool` to view metadata information about images.
```bash
exiftool <picture>
```

- We can check if there is any hidden data inside an image using `binwalk`.
```shell
binwalk <picture>
```

- To extract the hidden files if there are any, use the `-e` flag.
```shell
binwalk -e <picture>
```

- We can also check for steganography, or storing information inside images using the `steghide` tool.
```shell
steghide info <picture>
```

- If we find something that we can extract, we can use the `--extract -sf` flags.
```shell
steghide --extract -sf cute-alien.jpg 
```

---
### Decompressing Compressed Files

There are various types of compression mechanisms, such as `bzip2`, `tar`, `gzip`, and so on.
- In order to determine which compression type is being used, either use the `file` command, or observe the hexdump of the file using the `xxd` tool and check the file's signature.
- The signature can be compared using this [list](https://en.wikipedia.org/wiki/List_of_file_signatures).

> In order to properly de-compress files, they must be renamed with the extension of the compression algorithm used. Use the `mv` command to achieve this.

---
### JSON Files

To deal with JSON files, use the `jq` tool.

Can be used to extract the value of a certain field from a file:
```bash
jq .[].arg1.arg2 filename.json -r
```
- The `-r` is top return it as a string.

---
