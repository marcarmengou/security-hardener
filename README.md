# Description

**Security Hardener** applies WordPress security best practices based on the [WordPress Advanced Administration / Security / Hardening](https://developer.wordpress.org/advanced-administration/security/hardening/) documentation. It uses WordPress core functions and does not modify core files.

It is a hardening tool, not a firewall or a malware scanner: it reduces your attack surface, and its checklist points out measures that have to be applied on your server.

## Key Features

**Files and updates:**
* Disable the file editor in WordPress admin
* Optionally disable all file modifications (blocks updates and installations)

**XML-RPC and pingbacks:**
* Disable XML-RPC completely, or keep it and remove only its pingback methods
* Remove the X-Pingback header and block incoming and self-pingbacks

**User enumeration:**
* Block `/?author=N` queries (returns 404) and the canonical redirects that expose usernames
* Require login for REST API user endpoints and remove users from XML sitemaps
* Optionally block author feed pages (`/author/username/feed/`)
* Optionally anonymize the author name in oEmbed responses

**Login security:**
* Generic error messages (no username/password hints)
* Login honeypot to silently block bots
* Block registration of unsafe usernames (admin, root, test…)
* Application Passwords disabled by default
* IP-based rate limiting with configurable thresholds
* Security event log (last 100 events, including IP addresses and usernames of failed attempts)

**Security headers:**
* `X-Frame-Options: SAMEORIGIN` and `X-Content-Type-Options: nosniff`
* `Referrer-Policy: strict-origin-when-cross-origin`
* `Permissions-Policy: geolocation=(), microphone=(), camera=()`
* Optional HSTS for HTTPS sites (max-age of 1 year, with optional `includeSubDomains` and `preload`)

**Additional hardening:**
* Hide the WordPress version (meta generator tag and asset query strings)
* Remove obsolete `wp_head` items (RSD, WLW manifest, shortlink, emoji scripts)
* System Status: file permissions, WP_DEBUG, user registration, administrator accounts, PHP version, and database version
* Interactive hardening checklist with saved progress, for measures that must be applied on your server

> ⚠️ **Important:** Always test security settings in a staging environment first. Some features may affect third-party integrations or plugins.

**Privacy:** This plugin does not send data to third parties and does not create custom database tables. It stores its settings, checklist progress, and a security event log in the WordPress options table. The log keeps the last 100 events, including IP addresses and the usernames used in failed login attempts, until you clear it. Login attempt tracking uses short-lived transients keyed by a hash of the IP address. The PHP check in System Status uses WordPress core's cached recommendation, which core may refresh from api.wordpress.org. All data is preserved on uninstall by default and only deleted if you explicitly enable "Delete all data on uninstall".

## Resources
WordPress Plugin Repository: [https://wordpress.org/plugins/security-hardener/](https://wordpress.org/plugins/security-hardener/)
