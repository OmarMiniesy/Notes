
### Zip files

> We can unzip zipped files using the command:

```bash
7z e <zip-file>
```

> If we cannot because it is password, we can use [[John the Ripper#zip2john]].

---

### Images

>  We can use the `exiftool` to view metadata information about images.

```bash
exiftool <picture>
```

> We can check if there is any hidden data inside an image using `binwalk`.

```shell
binwalk <picture>
```

> To extract the hidden files if there are any, use the `-e` flag.

```shell
binwalk -e <picture>
```

> We can also check for steganography, or storing information inside images using the `steghide` tool.

```shell
steghide info <picture>
```

> If we find something that we can extract, we can use the `--extract -sf` flags.

```shell
steghide --extract -sf cute-alien.jpg 
```

---

