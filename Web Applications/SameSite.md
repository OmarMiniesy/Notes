### General Notes

Used to prevent [[Cross Site Request Forgery (CSRF)]] attacks.

---
### What is a Site ? 

A site is defined as the top-level domain (TLD). [[Domain Name System (DNS)#DNS Structure]], plus one additional level of the domain name. This is the *TLD + 1*.

- To determine if requests are coming from the same site, the URL scheme, or basically [[HTTP]] or [[HTTPS]], is also added to the site.

- An origin is only one domain name, while a site has multiple domain names.

```
https://app.example.com:443
1-------2-----3------4---5

1: scheme
4: TLD
5: Port
3 + 4 : TLD + 1
1 + 3 + 4 : site
1 + 2 + 3 + 4 + 5 : Origin
```
- [[Port]] is inferred from scheme.

---
#### What is SameSite ?

Reduces exposure to cross-site attacks by limiting the [[Cookies]] sent by cross-site requests.

There are 3 SameSite restriction levels:
* `Strict`.
* `Lax`.
* `None`.

Including the `SameSite` cookie with either of these values configures the restriction level for each cookie that is set.
- `Lax` is applied by default in Chrome, and maybe in the other major browsers.

1. `SameSite=Strict`: Cookies set with this attribute are not sent in any cross-site requests. Meaning if the target site of the request and the site in the address bar are not matching, the cookies will not be sent.
2. `SameSite=Lax`: Cookies set with this attribute are sent in cross-site requests only if the request is an [[HTTP]] `GET` request, and the request resulted from a top level navigation by the user (clicking on link). Meaning these cookies aren't sent in background requests such as those created by scripts, iframes, or images.
3. `SameSite=None`: Disables the SameSite restrictions, and cookies are sent normally. When it is set, the website must include the `secure` attribute for the cookies to be transmitted only in encrypted [[HTTPS]] messages. If `None` is seen, it is worth investigation.
```
Set-Cookie: trackingId=0F8tgdOhi9ynR1M9wa3ODa; SameSite=None; Secure
```

---
