
### General Notes

> Information leakage.
> Website reveals sensitive information to users.

> Examples:
1. `robots.txt` file or directory listing. [[Access Control]].
2. Access to source code via temp backups.
3. Mentioning database information in error messages.
4. Exposing highly sensitive information.
5. Hard-coding [[Application Programming Interface (API)]] keys, [[IP]] addresses, database credentials.
6. Hinting at the existence of missing or incorrect fields via different responses.

---

### Fuzzing

> Submit unexpected data types and crafted fuzz strings to see the effects.
> Responses can hint at the application behaviour, such as time taken or different error messages.

> Using [[Burp Suite]] Intruder, add payload positions, identify difference in [[HTTP]] responses (length, status code, response times), grep matching rules, and grep extraction rules.

Using `cewl`, we can scrape a website and take keywords:
```bash
cewl -m5 --lowercase -w <path-to-save> <url>
```
> `-m5` finds all words with minimum length of 5.
> `--lowercase` converts them all to lowercase.
> These words are then saved into the wordlist using `-w`.

Using ffuf, we can then try and fuzz for any files using this wordlist, in companionship with the `raft` seclists wordlists for extensions, as well as the `wp-admin`, `wp-content`, `wp-includes` folders that might contain sensitive information.

```bash
ffuf -w /folders.txt:FOLDERS, /wordlist.txt:WORDLIST, /extensions.txt:EXTENSIONS -u http://yahoo.com/FOLDERS?WORDLISTEXTENSIONS
```
> Saving the folders, extensions, and wordlists above into these file names, we can fuzz for sensitive information on the website using them.


---

### Sources of Information Disclosure

##### Files For Web Crawlers

> Websites give the crawlers files to navigate their sites, and which directories to skip.
> They might not appear on [[Burp Suite]] site map, so navigate to them manually.

```
/robots.txt
/sitemap.xml
```

##### Directory Listings

> Web servers are automatically configured to list contents of directories that have no index page.
> Can help attackers to identify which resources to attack.
> Increases exposure of sensitive files such as temporary files and crash dumps.

##### Developer Comments

> Sometimes comments contain information that might be useful for attackers.
> Hint at existence of hidden directories or inform about the application logic.

##### Error Messages

> Verbose error messages can reveal information about data types required, identify exploitable parameters, and know which payloads won't work.
> Can also reveal technology used by websites, template engine, database type, or server and its version.

> This can help us search for developed exploits, common configuration errors, or dangerous settings.
> Also if the website uses publically available source code.

> Sometimes, these error messages can contain: 
1. Values for [[Sessions]] variables.
2. Hostnames and credentials for backend components.
3. Files and directory names.
4. Keys used to encrypt data.

##### Debugging Information

> Similar to error messages.
> Logs can also be contained in a separate file.

##### Source Code Disclosure Via Backup Files

> Identifying if there is an open source technology in use.
> Sensitive data can be hard coded within the source code, such as [[Application Programming Interface (API)]] keys or credentials.

> Reading the code files itself, but requesting them doesn't reveal their contents.
> Temporary backup files are generated while original file is being edited, indicated by a `~` appended or a different file extension.
> Requesting these backup files can sometimes work.

##### Insecure Configuration

> [[HTTP]] `TRACE` method is used for testing.
> The web server responds with the exact request that was sent.
> Can lead to disclosure of internal authentication headers.

##### Version Control History

> Websites are developed using version control systems, such as Github, or Git.
> This version control data is stored in a folder called `.git`.
> Can be accessed `/.git` sometimes.

> Downloading it or viewing it shows logs of committed changes, and see small snippets of code.
> Morover, sensitive data could be hard coded and uploaded.

---

### Preventing Information Disclosure Vulnerabilities

* Inform developers which data is sensitive.
* Test code for potential disclosures.
* Use generic error messages.
* Make sure that debugging features are disabled.
* Understand any 3rd party configurations, settings, security risks.

---
