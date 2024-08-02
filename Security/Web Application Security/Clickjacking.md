
### General Notes

A user is tricked into clicking on actionable content in a decoy website, leading to victims submitting their data to false sources.

> Clickjacking attacks are not mitigated by the [[CSRF]] token as a target session is established with content loaded from an authentic website and with all requests happening on-domain.

> Can use [[Burp Suite]]'s Clickbandit tool to create clickjacking payloads.
---

### Constructing a clickjacking attack

Using `CSS` to create multiple layers.
- The `iframe` with the target website is placed overlapping the decoy.
- The target is made to have 0 `opacity` such that the decoy appears, making the target invisible.

So when the user thinks he is clicking on the decoy, he is actually clicking on the target website.

```HTML
<head> 
	<style> 
		#target_website { 
			position:relative; 
			width:128px; 
			height:128px; 
			opacity:0.00001; 
			z-index:2; 
		} 
		#decoy_website { 
			position:absolute; 
			width:300px; 
			height:400px; 
			z-index:1; 
		} 
	</style> 
</head>
<body> 
	<div id="decoy_website"> ...decoy web content here... </div> 
	<iframe id="target_website" src="https://vulnerable-website.com"> </iframe> 
</body>
```
> Using `z-index` to place layers, the larger appears on top.
> Opacity is set by default in browser to counteract click-jacking, therefore, the opacity styling must be placed.
> The `relative` and `absolute` positioning is used to keep the target on top of the decoy with these `width` and `height` values.

##### Clickjacking with prefilled form

Some websites permit forms to be prepopulated using [[HTTP]] `GET` parameters.
- The target URL can be modified to include such input values.
- Done by changing the `src` in the `iframe` above to include the form parameters that are to be prefilled.

###### Clickjacking with [[Cross Site Scripting (XSS)]]

Identifying the XSS exploit on the website.
- The XSS payload is combined with the `iframe` URL so that when the user clicks, the XSS attack is also carried out.

---
### Frame Busting

The clickjacking technique works when we are able to put a website into an `iframe`, or a frame.
- There are client-side protection techniques to use frame busting or frame breaking scripts.

This is done through JavaScript add-ons or extensions, such as `NoScript`, and they: 
1. Check that the current application window is the main/top window.
2. Make all frames visible.
3. Prevent clicking on invisible frames.
4. Intercept and flag potential clickjacking attacks.

To work around the frame busting scripts, we use the `sandbox` attribute for `iframe`s.
- This attribute can be set with the values `allow-forms` or `allow-scripts`, removing the value `allow-top-navigation`.
- These values allow for actions within the `iframe`s, but disallows top-level navigation (clicking on links, etc..).

```HTML
<iframe id="victim_website" src="https://victim-website.com" sandbox="allow-forms"></iframe>
```

---

### Preventing clickjacking

* `X-Frame-Options`: response header that provides website owner with control over `iframe`s or objects so that no webpage can be included inside frames.
	* `X-Frame-Options: deny`: prohibits it.
	* `X-Frame-Options: sameorigin`: framing is restricted only to the same origin.
	* `X-Frame-Options: allow-from x.com`: framing from a given named website.

* CSP([[Cross Site Scripting (XSS)#Content Security Policy (CSP)]]): detection mechanism that provides mitigation against attacks such as XSS and Clickjacking: implemented as a return header: `Content-Security-Policy: policy`.

> `policy` is a list of directives separated by semicolons.

The recommended clickjacking protection is to incorporate the `frame-ancestors` directive in the application's Content Security Policy. 
* The `frame-ancestors 'none'` directive is similar in behavior to the X-Frame-Options `deny` directive. 
* The `frame-ancestors 'self'` directive is broadly equivalent to the X-Frame-Options `sameorigin` directive. 
* The following CSP whitelists frames to the same domain only: `Content-Security-Policy: frame-ancestors 'self';`
*  Alternatively, framing can be restricted to named sites: `Content-Security-Policy: frame-ancestors normal-website.com;`.

---
