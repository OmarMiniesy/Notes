
### General Notes

> Widening the attack surface by discovering the websites owned by the same organization.
> Websites share the same top-level domain name.
> Through subdomain enumeration, we can identitfy additional resources of a target.

> These resources may contain outdated, buggy software, sensitive information, or admin areas that are not secure.

> These are only discoverable if they are made public, that is they are found on public [[Domain Name System (DNS)]] records.
> To discover non-public subdomains, we do VHost ([[Name Based Virtual Hosting]]) enumeration. 

---
### Public Subdomains - [Cheat Sheet](https://pentester.land/blog/subdomains-enumeration-cheatsheet/)
###### 1. Using [Subfinder](https://github.com/projectdiscovery/subfinder)

* [Guide](https://blog.projectdiscovery.io/do-you-really-know-subfinder-an-in-depth-guide-to-all-features-of-subfinder-beginner-to-advanced/).
```
subfinder -d <link> -cs -o subdomainswithsources
```
> Gets the subdomains and their sources as well (`cs`). The `-o` to save in output file.
> Can then get only the subdomains with sources using `grep`.
```
cat subdomainswithsources | grep -d "," -f 1 > subdomains
```

###### 2. Using [Sublist3r](https://github.com/aboul3la/Sublist3r)

###### 3. Using [amass](https://github.com/owasp-amass/amass)

* [Guide](https://github.com/owasp-amass/amass/blob/master/doc/user_guide.md).
```
amass enum -d <link> -options
```

###### 4. Using [waybackurls](https://github.com/tomnomnom/waybackurls)

* [Guide](https://www.geeksforgeeks.org/waybackurls-fetch-all-the-urls-that-the-wayback-machine-knows-about-for-a-domain/).
```
./waybackurls <domain> > urls.txt
```
 
###### 5. Using [crt.sh](https://crt.sh/)

> Get information about domains and lists domains for organizations.
> Check for dev and admin domains.

To save the subdomains using `crt.sh`:
``` bash
curl -s https://crt.sh/?q=<DOMAIN>&output=json | jq -r '.[]' "\(.name_value)\n\(.common_name)"' | sort -u > "<DOMAIN>_crt.sh.txt"
```

###### 6. Using [ffuf](https://github.com/ffuf/ffuf)

```
ffuf -u https://FUZZ.yahoo.com/ -w /usr/share/wordlists/seclists/Discovery/DNS/<wordlist> -p 1
```
> `-p` for delay between requests.

---

### Non-public Subdomains and VHosts

> These non-public subdomains can be discovered by doing VHost fuzzing on a given [[IP]] address.

Since VHosts are differentiated according to the value of their `host`, we can fuzz this [[HTTP]] header and see which responses have proper sizes that indicate the presence of an existing page.

> The IP address must be added to the `/etc/hosts` file before running.
```
ffuf -u https://yahoo.com/ -w /usr/share/wordlists/seclists/Discovery/DNS/<wordlist> -H 'Host: FUZZ.yahoo.com' -fs <size>
```
> We fuzz the `host` header using the `-H` flag.
> All responses will be `200 OK` since we are only changing the headers, but when a response returns and actual existing page, the size should be different.
> Filter on the repeated size to see the pages that are different using `-fs`.

---
