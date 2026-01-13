### General Notes

Below are typical characteristics phishing emails have in common:
- The **sender email name/address** will masquerade as a trusted entity- ([email spoofing](https://www.proofpoint.com/us/threat-reference/email-spoofing))
- The email subject line and/or body (text) is written with a **sense of urgency** or uses certain keywords such as **Invoice**, **Suspended**, etc. 
- The email body (HTML) is designed to match a trusting entity (such as Amazon)
- The email body (HTML) is poorly formatted or written (contrary from the previous point)
- The email body uses generic content, such as Dear Sir/Madam. 
- **Hyperlinks** (oftentimes uses URL shortening services to hide its true origin)
- A [malicious attachment](https://www.proofpoint.com/us/threat-reference/malicious-email-attachments) posing as a legitimate document

Hyperlinks and IP addresses should be **defanged**
- Defanging is a way of making the URL/domain or email address unclickable to avoid accidental clicks, which may result in a serious security breach. 
- It replaces special characters, like `@` in the email or `.` in the URL, with different characters. 
- For example, `http://www.suspiciousdomain.com`, will be changed to `hxxp[://]www[.]suspiciousdomain[.]com` .

To collect any links or URLs without clicking on them:
- right click on the link and choose `copy link location`.
- use tools like CyberChef to extract URLs

To check the reputation of files, we can save the file without opening it.
- we can obtain the hash of the file using `sha256sum` for example.
- we can then use a [[Cyber Threat Intelligence]] tool to get more information about it.

###### Checklist to Collect

**Email Header:**
- Sender email address
- Sender [[IP]] address
- Reverse lookup of the sender IP address
- Email subject line
- Recipient email address (this information might be in the CC/BCC field)
- Reply-to email address (if any)
- Date/time

**Email Body & Attachments**:
- Any URL links (if an URL shortener service was used, then we'll need to obtain the real URL link)
- The name of the attachment
- The hash value of the attachment (hash type MD5 or SHA256, preferably the latter)

---
### Email Header

This [resource](https://web.archive.org/web/20221219232959/https://mediatemple.net/community/products/all/204643950/understanding-an-email-header) is nice in analyzing the header of the email address.
- Another important thing to do is to view the email as a raw message.
- Check out the tools [Google Admin Toolbox Messageheader](https://toolbox.googleapps.com/apps/messageheader/analyzeheader), [Message Header Analyzer](https://mha.azurewebsites.net/),  [mailheader.org](mailheader.org) to analyze email headers.

Some important headers:
1. `X-Originating-IP` - The IP address of the email was sent from (this is known as an [X-header](https://help.returnpath.com/hc/en-us/articles/220567127-What-are-X-headers-))
2. `Smtp.mailfrom/header.from` - The domain the email was sent from (these headers are within Authentication-Results)
3. `Reply-To` - This is the email address a reply email will be sent to instead of the From email address. This is also the same as `Return-Path`.

Can also utilize [[Cyber Threat Intelligence#OSINT CTI Tools|Threat Intelligence Tools]] to analyze data in this headers and see if it is malicious.
- Can be used to check the reputations of IPs, domains, and URLs.

### Email Body

This can be text or HTML.
- Viewing the source code of the email allows us to deeply inspect the content and the attachments.

Some URLs can be shortened to prevent the user from knowing where the link will take you.
- Can be decoded by using tools that show the destination page.

Tracking pixels can be embedded in the email to collect information about what happens after the message is sent. It collects data like if the message was opened, where, by who, and if any links were clicked inside the email.
- Can be detected by inspecting the source code and looking for images with `1x1` dimensions and if the source is a URL.

Some attachments in the body should be analyzed in *malware sandboxes* to see how it operates, what it communicates with, and other Indicators of Compromise that can be extracted.
- Some online sandboxes to visit are [any.run](https://app.any.run/), [Hybrid Analysis](https://www.hybrid-analysis.com/), and [Joe Security](https://www.joesecurity.org/).

---

