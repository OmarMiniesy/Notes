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

---
### Local File Inclusion (LFI)

Identify injection points where attacker input can change the data being displayed to reveal files.
- Using techniques from the [[Directory Traversal]] note, attackers can bypass defenses that are put in place to protect against file inclusion vulnerabilities.
- Check out also [[Command Injection]] note for more complex techniques to bypass filters.

##### Using PHP Filters

We can use `php` filters, which are a type of `php` wrappers that can take input and filter it in a defined manner by the type of filter used.
- The `filter` wrapper has 2 important parameters, which are `resource` and `read`, that define how to apply the filter and the resource file to be applied on.

The base64 conversion filter is useful in disclosing source code, and it can be used by specifying the file name:
```url
php://filter/read=convert.base64-encode/resource=filename
```
- The filename can be discovered by using a fuzzing tool as part of [[Directory and File Enumeration]] with a *fixed* file type extension at the end of `.php`.

---
