
### General Notes

> Widening the attack surface by discovering the websites owned by the same organization
> Websites share the same top-level domain name.
> Through subdomain enumeration, we can identitfy additional resources of a target.

> These resources may contain outdated, buggy software, sensitive information, or admin areas that are not secure.

---
### Tools - [Cheat Sheet](https://pentester.land/blog/subdomains-enumeration-cheatsheet/)
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
---
