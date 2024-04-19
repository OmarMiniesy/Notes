### Open Source Intelligence

Exploiting information available on social networks and public sites.
- Check out integrated accounts.

>Figure out if there is an email schema. Mail systems inform the sender that mail wasn't delivered because user doesn't exist.

- [[Subdomain Enumeration]] is also OSINT.
- Google Dorks as well in [[Google Hacking]].
---

### Gathering Information

Gathering emails: 
* hunter.io
* phonebook.cz
* emailhippo: check if emails exist.
* clearbit
* email-checker.net

>Breached passwords for emails.
* dehashed.com

---

### Tools

##### Amass
> Tool for gathering information about webpages, such as subdomains, ASNs, etc..

##### Arjun
> [Arjun](https://github.com/s0md3v/Arjun) finds hidden parameters in URLs and [[Application Programming Interface (API)]] endpoints.

##### CrunchBase
> [CrunchBase](http://www.crunchbase.com) is a database where details about founders, investors, buyouts, and acquisitions

##### httpx

> Used to send requests asynchronously and get information about domains.
> Title, wordcount, wordlength, status code, etc.. 

##### [netcraft](http://netcraft.com)
> Used to get ISP's and useful information regarding the domains and IP addresses.

##### Subfinder
> [subfinder](https://github.com/projectdiscovery/subfinder) is an online passive scanning tool that looks for subdomains.

##### Whois
> Whois database has information about owner, street address, email address, and technical contacts of an Internet domain.
> Shows the name servers used by the target as well.
> Can also get the [[IP]] addresses of several machines. 

##### Whatweb, Netcat
> Used to get information about the server infrastructure.

##### WafW00f
Used to identify firewalls and other security mechanisms.
```
wafw00f -v -a <URL>
```
> `-a` scans all firewalls and doesn't stop after first match.

##### [wigle.net](https://wigle.net)
> Takes `BSSID` and `SSID` to get geographic location.

---
