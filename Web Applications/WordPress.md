### General Notes

This is an open source **CMS**, or content delivery system.
- Used to host websites of different sorts, like blogs, forums, and e-commerce websites.
-  It has a large library of extensions called themes and plugins, both free and paid.

> This high customizability of WordPress makes it vulnerable through the third party themes and plugins.

WordPress is written in `PHP` and usually runs on `Apache` with `MySQL` as the backend.
- It relies on the *LAMP* stack, where the operating system is `Linux`.

---
### WordPress Structure

- All the WordPress files and folders can be found in the Webroot:
```
/var/www/html
```

- Some of the important files that can be found in this directory:
```bash
├── index.php
├── license.txt
├── readme.html
├── wp-activate.php
├── wp-admin
├── wp-blog-header.php
├── wp-comments-post.php
├── wp-config.php
├── wp-config-sample.php
├── wp-content
├── wp-cron.php
├── wp-includes
├── wp-links-opml.php
├── wp-load.php
├── wp-login.php
├── wp-mail.php
├── wp-settings.php
├── wp-signup.php
├── wp-trackback.php
└── xmlrpc.php
```
##### Important Files

- `index.php` is the homepage of WordPress.
- `license.txt` contains useful information such as the version WordPress installed.
- `wp-activate.php` is used for the email activation process when setting up a new WordPress site.
- `wp-admin` folder contains the login page for administrator access and the backend dashboard. Once a user has logged in, they can make changes to the site based on their assigned permissions. The login page can be located at one of the following paths:
    - `/wp-admin/login.php`
    - `/wp-admin/wp-login.php`
    - `/login.php`
    - `/wp-login.php`
- `xmlrpc.php` is a file representing a feature of WordPress that enables data to be transmitted with HTTP acting as the transport mechanism and XML as the encoding mechanism. This type of communication has been replaced by the WordPress [REST API](https://developer.wordpress.org/rest-api/reference).
- The `wp-config.php` file contains information required by WordPress to connect to the database, such as the database name, database host, username and password, authentication keys and salts, and the database table prefix. This configuration file can also be used to activate DEBUG mode, which can useful in troubleshooting.
- The `wp-content` folder is the main directory where plugins and themes are stored. The subdirectory `uploads/` is usually where any files uploaded to the platform are stored.

---
### User Roles

There are several user roles in WordPress, with each role having a set of permissions.

| Role          | Permissions                                                                                                                                            |
| ------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Administrator | This user has access to administrative features within the website. This includes adding and deleting users and posts, as well as editing source code. |
| Editor        | An editor can publish and manage posts, including the posts of other users.                                                                            |
| Author        | Authors can publish and manage their own posts.                                                                                                        |
| Contributor   | These users can write and manage their own posts but cannot publish them.                                                                              |
| Subscriber    | These are normal users who can browse posts and edit their profiles.                                                                                   |

> In order to gain remote code execution, `administrator` access is often sought after. However, `authors` and `editors` can have access to plugins that are vulnerable as well.

---

