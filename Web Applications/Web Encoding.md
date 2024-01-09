
### General Notes

> Web page content is displayed part of a character set.

> Character encoding is a representation in bytes of the symbols of a character set.

---

### HTML Entity

> To show symbols in web documents and to not be interpreted as HTML elements, use HTML entities.

> Used to limit client side attacks such as [[Cross Site Scripting (XSS)]].

> An HTML entity is a string starting with `&` or `&#` and ending with `;` .

> When a browser sees an HTML entity, it will show the symbol to the user and will not interpret it as HTML language.

> For a character, check the name from this [list](https://html.spec.whatwg.org/multipage/named-characters.html#named-character-references).
> Then to encode it `& + name + ;` such as `&lt;`.

> For a number encode it as such `&# + D + ;`. Where `D` is the number.

> For a hexadecimal encode it as such `&# + xH + ;`. Where `H` is the case insensitive hex.

---

### URL Encoding / Percent-Encoding

> Some characters are encoded using the `%` character and 2 hex digits.
> URLs only display characters that are ASCII. Therefore, encoding is needed for those outside ASCII and some special dangerous ASCII characters.

> Web browsers perform URL encoding and server side engines perform decoding.

> [Encoding Reference](https://www.w3schools.com/tags/ref_urlencode.asp).

---

### Base64

> Binary to text encoding to convert binary files and send them.
> Used by HTML to include resources such as an image's binary content after being converted to base64.

---
